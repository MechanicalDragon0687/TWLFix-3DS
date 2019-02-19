#include <fstream>
#include <string>

bool fileExists(std::string filename) {
	// could include sys/stat but why bother?

	std::ifstream fs(filename);
	if (!fs) {
		return false;
	}
	return true;
}
