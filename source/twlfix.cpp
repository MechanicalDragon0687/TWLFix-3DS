
#include "3ds.h" //3ds libraries from devkitpro
#include <string>
#include <sstream> // obviously for the string manipulation and the string streams
#include <iomanip>
#include <iostream> // cout and io manipulation like std::setw
#include <fstream> // files
#include <vector> // vector of u64 for titles
#include <algorithm> // the copy routines
#include <cstring>
#include "crypto.h"
#include "twl.hpp"
#include "twlfix.hpp"

// We use vectors to avoid sending the array size and to allow us to iterate through any size list.
// This also lets us remove and add items on the list as necessary; it is not necessary here.
// For this application, realistically std::array or just a standard C array would suit our functions just as well
// Also, its my code and i'll do what i want to so vectors it is.

using std::cout;

extern u8 normalKey[0x10];
extern u8 normalKey_CMAC[0x10];
extern u8* ctcert;

//Read file and pass arguments along with file data to build broken TADs from a list of any size
Result buildBrokenTADfromSource(std::string srcFile, std::vector<u64> *uvTID, std::string iconfile) {
	std::ifstream fs(srcFile, std::ios::binary);
	if (!fs) {
		cout << "Cannot find source TAD: " << srcFile << "\n";
		return MAKERESULT(RL_PERMANENT, RS_NOTFOUND, RM_FILE_SERVER, RD_NOT_FOUND); // makeresult is part of result.h. this is included with 3ds.h. 
	}
	fs.seekg(0,std::ios::end); // move to EOF
	int flen = fs.tellg(); // returns pos_type, 
	if (flen > 0x1400000) { // check if filesize is more than 20mb
		cout << "Source DSiWare is too large.\n";
		return MAKERESULT(RL_PERMANENT, RS_NOTSUPPORTED, RM_FILE_SERVER, RD_TOO_LARGE);
	}
	// allocate dsiware memory and initialize data with 0s
	u8* dsiware = new u8[flen]();
	fs.seekg(0); // reset read position
	fs.read((char*)dsiware,flen); // read the file
	if (fs.gcount() < flen) { // check if we read the entire file or it failed
		cout << "Could not read all of DSiWare.\n";
		fs.close();
		return MAKERESULT(RL_PERMANENT, RS_OUTOFRESOURCE , RM_FILE_SERVER, RD_NO_DATA);
	}
	fs.close();
	Result res= buildBrokenTADfromSource(dsiware,flen,uvTID,iconfile); // call build function
	free(dsiware);
	return res;
}

// Using a byte array, build broken TADs from a list of any size. Also supports a custom banner.bin
Result buildBrokenTADfromSource(u8 *dsiware, u32 dsiware_size, std::vector<u64> *uvTID, std::string iconfile) {
	//Handle handle;
	Result res;

	u8 footer[SIZE_FOOTER]={0};

	u8 header_hash[0x20]={0};
	u8 header[SIZE_HEADER] = {0};

	u8 banner[SIZE_BANNER] = {0};
	u8 banner_hash[0x20]={0};
	u8 icon[0x220] = {0};
	if (dsiware == nullptr) {
		cout << "Source TAD data not found\n";
		return MAKERESULT(RL_PERMANENT, RS_NOTFOUND , RM_FILE_SERVER, RD_INVALID_POINTER);
	}
	// Read and decrypt data sections into memory
	getSection((dsiware + OFFSET_BANNER), SIZE_BANNER, normalKey, banner);
	getSection((dsiware + OFFSET_HEADER), SIZE_HEADER, normalKey, header);
	getSection((dsiware + OFFSET_FOOTER), SIZE_FOOTER, normalKey, footer);

	// === Icon File Check/Load
	// Banner icon and palette is 0x200+0x20
	if (iconfile!="") {
		cout << "\t Reading custom icon\t";
		std::ifstream bfs(iconfile, std::ifstream::binary);
		bfs.read((char*)icon,0x220);
		if (!bfs) { // if failbit is set, something went wrong with opening or reading, either way error that it cannot be read.
			cout << "Failed\nCannot read " << iconfile << "\n\n";
		}else{
			cout << "Success\n\n";
			bfs.close();
			// write static icon to memory. all dsiware copies will use the same icon.
			std::copy(icon,icon+0x220,banner+0x20);
			// Set banner type to non-animated icons
			banner[0x01] = 0x00;
		}
	}

	std::stringstream newFile("");
	for(std::vector<u64>::iterator uTID = uvTID->begin();uTID != uvTID->end(); ++uTID ) {
		newFile.str("");
		newFile << TWLFIX_OUTDIR << std::setw(8) << std::setfill('0') << std::hex << TIDLOW(*uTID) << std::setw(0) << ".bin";
		cout << "Creating " <<  newFile.str() << "\n";
		cout << "\tModifying header\n";
		std::copy_backward((char*)&*uTID,(char*)&*uTID+7,header+0x3f); // write TID in reverse byte order to header

		// === Header is now modified ===
		calculateSha256(header, SIZE_HEADER, header_hash);
		std::copy(header_hash,header_hash+0x20,footer+0x20);

		cout << "\tGenerating banner\n";
		// Banner titles are stored as UTF-16. Easiest way to replicate that with ascii assigned to 16bit int.
		// Open an issue and educate me if you know better.
		u8 * skinnyAppName = new u8[0x50]();
		std::stringstream AppTitle("");
		// App title is normally in the form of GAME\nSubTitle\nDeveloper
		// Here i am using it to give the user the idea of what to expect
		AppTitle << "Uninstall " << std::setw(8) << std::setfill('0') << std::hex << TIDLOW(*uTID) << std::setw(0) << "\nInstall should fail\nClick Copy to begin";
		AppTitle.read((char*)skinnyAppName,0x50);
		for (int i=0;i<8;i++) {
			std::copy(skinnyAppName,skinnyAppName+0x50,(u16*)(banner+0x240+(i*0x100))); // cast banner location to 16bit and copy the 8bit values to 16 bit memory locations. basically stretches the 8bit over 16bit
		}
		free(skinnyAppName);

		// === banner is now modified ===
		// banner header has crcs depending on type, might as well generate them all.
		fixcrc16((u16*)(banner+0x2), banner+0x20, 0x820);
		fixcrc16((u16*)(banner+0x4), banner+0x20, 0x920);
		fixcrc16((u16*)(banner+0x6), banner+0x20, 0xA20);
		fixcrc16((u16*)(banner+0x8), banner+0x1240, 0x1180);
		calculateSha256(banner, SIZE_BANNER, banner_hash);
		std::copy(banner_hash,banner_hash+0x20,footer+0x00);// footer stores banner hash at 0x00-0x1F;

		cout << "\tSigning new data\n";
		// sign footer
		res = doSigning(ctcert, (footer_t*)footer);
		if (R_FAILED(res)) {
			cout << "ERROR: SIGNING FAILED\n";
			return res;
		}
		// encrypt and replace sections in dsiware memory
		placeSection((dsiware + OFFSET_BANNER), banner, SIZE_BANNER, normalKey, normalKey_CMAC);
		placeSection((dsiware + OFFSET_HEADER), header, SIZE_HEADER, normalKey, normalKey_CMAC);
		placeSection((dsiware + OFFSET_FOOTER), footer, SIZE_FOOTER, normalKey, normalKey_CMAC);


		cout << "\tWriting file\n";
		// === WRITE FILE ===
		std::ofstream dfs(newFile.str(), std::ios::binary);
		dfs.write((char*)dsiware,dsiware_size);
		if (!dfs) {
			cout << "Error writing file.\n";
			std::remove(newFile.str().c_str()); // delete file if it exists already. i dont like std::remove, will probably replace sometime.
			return MAKERESULT(RL_PERMANENT, RS_OUTOFRESOURCE , RM_FILE_SERVER, RD_NO_DATA);
		}
		dfs.close();
		cout << "\tDone\n\n";
	} 
	return res;
}
