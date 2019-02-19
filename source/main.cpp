#include <3ds.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <fstream>
//#include <unistd.h>
#include "crypto.h"
#include "twl.hpp"
#include "twlfix.hpp"

#define SECOND(x) (x*1000ULL*1000ULL*1000ULL)
using std::cout, std::string, std::setfill, std::setw;
void writeAllBytes(string filename, u8 *filedata, u32 filelen);
u8 *readAllBytes(string filename, u32 &filelen);
void error( string errormsg, string filename, bool fatal);
bool StopOrGo(string msg);

PrintConsole topScreen, bottomScreen;

bool isN3ds=false;

u8 normalKey[0x10]={0};
u8 normalKey_CMAC[0x10]={0};
u8* ctcert;
u32 ctcert_size=0;

void importTadList(std::vector<u64> *tid) {
	std::stringstream fname("");
	for (std::vector<u64>::iterator cTID=tid->begin();cTID != tid->end();++cTID) {
		fname.str("");
		fname << TWLFIX_OUTDIR << std::setw(8) << std::setfill('0') << std::hex << TIDLOW(*cTID) << std::setw(0) << ".bin";
		cout << "Importing broken title: " << std::setw(16) << std::setfill('0') << std::hex << *cTID << std::setw(0) << "\t";
		import_tad(fname.str());
		cout << "Done\n";
	}

}

void error(string errormsg, string filename, bool fatal) {
	PrintConsole* oldCon = consoleSelect(&bottomScreen);
	cout << "\x1b[31m" << errormsg << "!\n\x1b[0m" << filename << "\n" << "Press [START] to exit";
	if (fatal) {
		while (1) {
			hidScanInput();
			if (hidKeysDown() & KEY_START) break; 
			gfxFlushBuffers();
			gfxSwapBuffers();
			gspWaitForVBlank();
		}

		exit(-1);
	}else{
		consoleSelect(oldCon);
	}
}

u8 *readAllBytes(string filename, u32 &filelen) {
	FILE *fileptr = fopen(filename.c_str(), "rb");
	if (fileptr == NULL) {
		error("Failed to open " + filename,"",true);
	}
	
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);

	u8 *buffer = new u8[filelen]();
	fread(buffer, filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

void writeAllBytes(string filename, u8 *filedata, u32 filelen) {
	FILE *fileptr = fopen(filename.c_str(), "wb");
	fwrite(filedata, 1, filelen, fileptr);
	fclose(fileptr);
}

Result DSiDump(u64 *tid) {

	Result res;
	*tid=0;

	std::cout << "Retrieving number of titles\t";
	u32 title_count=0;
	//u64 dsiTitle[50]={0};
	std::vector<u64> dsiTitle={};
	res = AM_GetTitleCount(MEDIATYPE_NAND, &title_count);
	cout << title_count << "\n";
	if (res) {
		cout << "\nFailed to get title count.\n";
		return res;
	}else{
		u64 *titleID; 
		titleID=new u64[title_count];
		u32 titles_read=0;
		res = AM_GetTitleList(&titles_read,MEDIATYPE_NAND,title_count,titleID);
		if (res) {
			cout << "Failed to get title IDs\n";
			return res;
		}else{
			title_count=0;
			std::string tfile(TWLFIX_OUTDIR);
			tfile += "TitleList.txt";
			std::ofstream tlist(tfile);
			for (u32 i=0;i<titles_read;i++) {
			
				u16 uCategory = TIDTYPE(titleID[i]);
				tlist << std::setw(16) << std::setfill('0') << std::hex << titleID[i] << std::setw(0) << "\r\n"; 			
				if (uCategory==0x8004 || uCategory==0x8005 /*|| uCategory==0x800F */|| uCategory==0x8015 ) {
//					title_count+=1;
					dsiTitle.push_back(titleID[i]);
				}else{
					if (titleID[i]==0x0004013820000002) { // if n3ds native firm installed, just in case earlier check didnt set this
						isN3ds=true;
					}
				}
			}
			tlist.close();
		}
		free(titleID);
	}
	for (std::vector<u64>::iterator iTID = dsiTitle.begin(); iTID != dsiTitle.end();++iTID) {
		if (TIDLOW(*iTID) == 0) {
			continue; // if TIDLOW is all 0s, keep going
		}
		cout << "Attempting to dump " << std::setw(8) << std::setfill('0') << std::hex << TIDLOW(*iTID) << std::setw(0) << "\t";

		res = export_tad(TWLFIX_OUTDIR, *iTID);		
		if (R_SUCCEEDED(res)) {
			cout << "Success\n";
				*tid = *iTID;
			return res;
		}else{
			cout << "Failed\nError Code: " << res << "\n";
		}
		//StopOrGo("");
	}
	return -1;
}
bool StopOrGo(string msg) {
	cout << msg << "\n";
	while (1) {
		hidScanInput();
		if (hidKeysDown() & KEY_A) { return true; }
		if (hidKeysDown() & KEY_START) { return false;}
	}
}

int main() {
	u8 * movable;
	u32 movable_size=0;
	//std::ios_base::sync_with_stdio(false);

	gfxInitDefault();
	consoleInit(GFX_TOP, &topScreen);
	consoleInit(GFX_BOTTOM, &bottomScreen);
	consoleSelect(&topScreen);

	Result res=0;
	u64 tid=0;
	cout << "Initializing APT services\n";
	aptInit();
	APT_CheckNew3DS(&isN3ds);
	cout << "Initializing FS services\n";
	res = fsInit();
	if (res) {
		cout << "Unable to initialize FS service\n";
		StopOrGo(" ");
		return res;
	}

	FS_Archive SDMCArchive;
	FSUSER_OpenArchive(&SDMCArchive, ARCHIVE_SDMC,fsMakePath(PATH_EMPTY, ""));
	std::string twlstr(TWLFIX_OUTDIR);
	twlstr=twlstr.substr(twlstr.find("/"),twlstr.length()-(twlstr.find("/")+1));
	FS_Path twlfix_path = fsMakePath(PATH_ASCII, twlstr.c_str());

	cout << "Removing existing " << twlstr << " directory.\n";
	res = FSUSER_DeleteDirectoryRecursively(SDMCArchive, twlfix_path);
	if (R_FAILED(res)) {
		cout << "Failed to delete " << TWLFIX_OUTDIR << ".\nError code: " << std::hex << res << "\n";
	}
	cout << "Recreating " << TWLFIX_OUTDIR << " directory.\n";
	FSUSER_CreateDirectory(SDMCArchive, twlfix_path, 0);
	FSUSER_CloseArchive(SDMCArchive);

	cout <<"Initializing ROMFS services\n"; 
	res = romfsInit();
	if (res) {
		StopOrGo("Unable to initialize ROMFS service\n");
		return res;
	}
	cout << "Initializing AM services\n";
	res = amInit();
	if (res) {
		StopOrGo("Unable to initialize AM service\n");
		return res;
	}
			svcSleepThread(SECOND(1));

	cout << "\nPress [A] to begin or [Start] to Exit!\n\n";
	
	while (1) {
		hidScanInput();
		if (hidKeysDown() & KEY_A) { break; }
		if (hidKeysDown() & KEY_START) { 
			amExit();
			//nsExit();
			gfxExit();
			fsExit();	
			return 0;
		}
	}

	cout << "Loading signing data\n";
	ctcert = readAllBytes("romfs:/ctcert.bin", ctcert_size);
	if (ctcert_size != 0x19E) {
		error("Provided certificate is not 0x19E in size","",true);
	}
	cout <<"Reading sdmc:/movable.sed\n"; 
	movable = readAllBytes("/movable.sed", movable_size);
	if (movable_size != 320 && movable_size != 288) {
		error("Provided movable.sed is not the correct size.","",true);
	}

	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	free(movable);

	res = DSiDump(&tid); // Dump any dsiware and return the title id
	if (res) {
		cout <<"Failed to dump any dsiware, please manually dump the dsiware and use the PC tools.\n"; 
		while (1) {hidScanInput(); if (hidKeysDown()) { break; } }
		free(ctcert);
		aptExit();
		amExit();
		gfxExit();
		fsExit();
		exit(0);
	}

	std::stringstream srcFile("");
	srcFile << TWLFIX_OUTDIR << setw(8) << setfill('0') << std::hex << TIDLOW(tid) << setw(0) << ".bin";	

	cout << "Breaking some DSiWare:\n";

	std::vector<u64> Breakables =  {
		0x0004800f484e4841,		// Whitelist
		0x0004800f484e4C41,		// Version Data
		0x0004800542383841,		// DS Internet
		0x00048005484E4441		// DS Dlp
	};

	if (isN3ds) {
		Breakables.push_back(0x0004013820000102); // N3DS TWL Firm
	}else{
		Breakables.push_back(0x0004013800000102);		// o3DS TWL Firm
	}

	cout << "\nCreating Broken DSiWare Exports \n";
	buildBrokenTADfromSource(srcFile.str(),&Breakables,"romfs:/icon.bin");
	//if (StopOrGo("Import DSiWare?\n")) {
		cout << "\n\n\nImporting Broken DSiWare Exports \n\n";
		importTadList(&Breakables);
	//}
	cout<<"\nDone!\n\nReboot and then open System Update.\nPress Start to reboot.";

	while (aptMainLoop()) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	} 
	free(ctcert);
	APT_HardwareResetAsync();
	amExit();
	fsExit();	
	aptExit();
	gfxExit();

	return 0;
}
