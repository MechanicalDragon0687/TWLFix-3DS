#ifndef TWLFIX_HPP__
#define TWLFIX_HPP__
#include "3ds.h"
//#include <iomanip>
//#include <iostream>
#include <vector>
#include <string>

#define TWLFIX_OUTDIR "sdmc:/TWLFix/"

// Builds broken DSiWare to force uninstall apps on 3ds
// Reads from file (srcFile)
Result buildBrokenTADfromSource(std::string srcFile, std::vector<u64> *uvTID, std::string iconfile="");
Result buildBrokenTADfromSource(u8 *dsiware, u32 dsiware_size, std::vector<u64> *uvTID, std::string iconfile="");

#endif