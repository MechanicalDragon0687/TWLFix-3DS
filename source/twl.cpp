#include <3ds.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include "twl.hpp"
#include "fs.hpp"
#include "ec.h"
#include "crypto.h"



const char *content_namelist[]={"tmd","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav"};

extern PrintConsole topScreen, bottomScreen;

// Import a backed up DSiWare (TAD)
// Using char16 due potential of SD supporting foreign languages like JPN
Result import_tad(std::string TADfile) {


	Handle handle; // eventually becomes the file handle to import
	Result res=0; // will return this value at the end to report success status or error state.

	// Generate archive path as empty
	//FS_Path archivePath = fsMakePath( PATH_EMPTY, "" );
	if (!fileExists(TADfile)) {
		std::cout << "\nCannot find file " << TADfile << "\n";
		return MAKERESULT(RL_PERMANENT, RS_NOTFOUND, RM_FILE_SERVER, RD_NOT_FOUND); // makeresult is part of result.h. this is included with 3ds.h. 
	}
	
	// Remove Drive designation
	TADfile = TADfile.substr(TADfile.find(":")+1); // find first :, then set tadfile to substring starting there to remove any beginning drive/mount point.
	// Build FSPath object from TADfile string
	//FS_Path filePath = fsMakePath(PATH_ASCII,TADfile.c_str());
	// get file handler for the TADfile by opening it from the SDMC archive (empty path = root of SDMC) as readonly
	res = FSUSER_OpenFileDirectly(&handle, ARCHIVE_SDMC, fsMakePath( PATH_EMPTY, "" ), fsMakePath(PATH_ASCII,TADfile.c_str()), FS_OPEN_READ, 0);
	if (R_FAILED(res)) {
		std::cout << "Failed to open file " << TADfile << "\n";
		return res;
	}
	// Import the opened TAD file. DSiWare operation 5 is used as it is one of 2 that are allowed to import on latest 3ds firm 
	u8* workbuf = new u8[0x20000](); 
	res = AM_ImportTwlBackup(handle, 5, workbuf, 0x20000);
	free(workbuf);
	// finally close the file handle 
	FSFILE_Close(handle);
	// if shit failed, let the calling function know
	return res;
}	

Result export_tad(std::string dir, u64 uTID) {
	PrintConsole *last = consoleSelect(&bottomScreen);

	Result res=0;
	std::stringstream ssFile("");
	// using a stringstream, set it to 8 characters wide, filling with 0 if needed. input the following value in hex.
	// TIDLOW defined as TIDLOW(x)  (x&0x00000000FFFFFFFFL) 
	// 4 LSB (32bits) of the 64bit TID
	// dont forget to reset width after (unnecessary here but always good practice)
	ssFile << dir << std::setw(8) << std::setfill('0') << std::hex << TIDLOW(uTID) << std::setw(0) << ".bin";
	if (fileExists(ssFile.str())) {
		std::cout << "\nFile " << ssFile.str() << " found.\n";
		consoleSelect(last);
		return MAKERESULT(RL_PERMANENT, RS_INVALIDSTATE, RM_FILE_SERVER, RD_ALREADY_DONE);
	}
	// DSiWare operation 5 used here as well
	// 
	u8 *workbuf = new u8[0x20000]();
	res = AM_ExportTwlBackup(uTID, 5, workbuf, 0x20000, ssFile.str().c_str());
	free(workbuf);
	if (R_FAILED(res)) {
		// it failed, remove file if it exists.
		std::remove(ssFile.str().c_str());
	}
	consoleSelect(last);
	return res;
}

void getSection(u8 *dsiware_pointer, u32 section_size, u8 *key, u8 *output) {
        decryptAES(dsiware_pointer, section_size, key, (dsiware_pointer + section_size + 0x10), output);
}


void placeSection(u8 *dsiware_pointer, u8 *section, u32 section_size, u8 *key, u8 *key_cmac) {
        u8 allzero[0x10]= {0};

        encryptAES(section, section_size, key, allzero, dsiware_pointer);

        u8 section_hash[0x20] = {0};
        calculateSha256(section, section_size, section_hash);
        u8 section_cmac[0x20] = {0};
        calculateCMAC(section_hash, 0x20, key_cmac, section_cmac);

		std::copy(section_cmac,section_cmac+0x10,dsiware_pointer + section_size );
        std::fill(dsiware_pointer + section_size + 0x10,dsiware_pointer + section_size + 0x20,0);
}

Result doSigning(u8 *ctcert_bin, footer_t *footer) {
	Result res;
	u8 ct_priv[0x1E], ap_priv[0x1E]={0}, tmp_pub[0x3C], tmp_hash[0x20];
	ecc_cert_t ct_cert, ap_cert={0};
	ap_priv[0x1D]=1;

	std::copy(ctcert_bin,ctcert_bin+0x180,(u8*)&ct_cert);
	std::copy(ctcert_bin+0x180,ctcert_bin+0x180+0x1e,ct_priv);
	
	ec_priv_to_pub(ct_priv, tmp_pub);
	if (!std::equal(tmp_pub, tmp_pub+0x3c, (char*)&ct_cert.pubkey)) {
		std::cout << "Error loading Cert keys\n";
		// TODO makeresult
		return -1;
	}

	std::copy((u8*)&footer->ap.key_id,(u8*)&footer->ap.key_id+0x40, (u8*)&ap_cert.key_id);
	std::stringstream apissuer("");
	apissuer << ct_cert.issuer << "-" << ct_cert.key_id;
	apissuer.read(ap_cert.issuer,sizeof(ap_cert.issuer));
	ap_cert.key_type = 0x02000000; // key type
	ec_priv_to_pub(ap_priv, ap_cert.pubkey.r);// pub key
	ap_cert.sig.type = 0x05000100;// sig


		int sanity=100;
	do {	
		calculateSha256((u8*)ap_cert.issuer, 0x100, tmp_hash);

		res = generate_ecdsa(ap_cert.sig.val.r, ap_cert.sig.val.s, ct_priv, tmp_hash);
		if (res < 0) {
			std::cout << "Error: Problem signing AP\n";
			continue;
		}

		calculateSha256((u8*)ap_cert.issuer, sizeof(ecc_cert_t)-sizeof(ap_cert.sig), tmp_hash);
		res = check_ecdsa(ct_cert.pubkey.r, ap_cert.sig.val.r, ap_cert.sig.val.s, tmp_hash);
		if (res != 1) {
			std::cout << "Bad AP Signature\n";
		}
		sanity--;
	} while(res !=1 && sanity >=0);

	sanity=100;
	do{
		calculateSha256((u8*)footer, 0x1A0, tmp_hash);
		res = generate_ecdsa(footer->sig.r, footer->sig.s, ap_priv, tmp_hash);
		if (res < 0) {
			std::cout << "Error: Problem signing footer\n";
			continue;
		}

		calculateSha256((u8*)footer, 0x1A0, tmp_hash);
		res = check_ecdsa(ap_cert.pubkey.r, footer->sig.r, footer->sig.s, tmp_hash);
		if (res != 1) {
			std::cout << "Bad Footer Signature\n";
		}
		sanity--;
	} while(res !=1 && sanity >=0);

	std::copy((u8*)&ap_cert,(u8*)&ap_cert+0x180,(u8*)&footer->ap);
	std::copy((u8*)&ct_cert,(u8*)&ct_cert+0x180,(u8*)&footer->ct);

	return 0;
}

void fixcrc16(u16 *checksum, u8 *message, u32 len){
	u16 original=*checksum;
	u16 calculated=crc16(message, len);
	if(original != calculated){
		*checksum=calculated;
		return;
	}
}
