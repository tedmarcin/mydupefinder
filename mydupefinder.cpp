/*
 *  mydupefinder - A command-line tool to detect and remove duplicate files.
 *  Copyright (C) 2025  TedMarcin
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <ctime>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <limits>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>

// ------------------------------------------------------------------------------------
// Function: getCurrentDateTime
// Retrieves the current date and time in the format YYYYMMDDHHMMSS
// ------------------------------------------------------------------------------------
std::string getCurrentDateTime() {
    std::time_t now = std::time(nullptr);
    std::tm *ltm = std::localtime(&now);
    char buf[16];
    std::strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", ltm);
    return std::string(buf);
}

// ------------------------------------------------------------------------------------
// Function: formatDuration
// Formats a given duration (in seconds) into the format h,mm,ss
// ------------------------------------------------------------------------------------
std::string formatDuration(int seconds) {
    int h = seconds / 3600;
    int m = (seconds % 3600) / 60;
    int s = seconds % 60;
    std::ostringstream oss;
    oss << h << "h," << std::setfill('0') << std::setw(2) << m << "m," << std::setw(2) << s << "s";
    return oss.str();
}

// ------------------------------------------------------------------------------------
// Function: getHash
// Calculates the hash of a file based on the given algorithm (MD5 or SHA-256)
// ------------------------------------------------------------------------------------
std::string getHash(const std::string& filepath, const std::string& algorithm = "MD5") {
    std::string output;
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << filepath << std::endl;
        return "";
    }
    try {
        if (algorithm == "MD5") {
            CryptoPP::Weak::MD5 hash;
            CryptoPP::FileSource fs(file, true, new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
        } else if (algorithm == "SHA-256") {
            CryptoPP::SHA256 hash;
            CryptoPP::FileSource fs(file, true, new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
        } else {
            std::cerr << "Invalid hash algorithm: " << algorithm << std::endl;
            return "";
        }
    } catch (const std::exception &e) {
        std::cerr << "Hash error for file " << filepath << ": " << e.what() << std::endl;
        return "";
    }
    return output;
}

// ------------------------------------------------------------------------------------
// Function: isPathInDirectory
// Checks whether the given file path is located within the specified directory
// ------------------------------------------------------------------------------------
bool isPathInDirectory(const std::string& filePath, const std::string& directory) {
    try {
        std::filesystem::path fileP = std::filesystem::canonical(filePath);
        std::filesystem::path dirP = std::filesystem::canonical(directory);
        auto relPath = std::filesystem::relative(fileP, dirP);
        return !relPath.empty() && relPath.string().find("..") == std::string::npos;
    } catch (const std::exception &e) {
        std::cerr << "Error comparing paths: " << e.what() << std::endl;
        return false;
    }
}

// ------------------------------------------------------------------------------------
// Main function
// ------------------------------------------------------------------------------------
int main(int argc, char **argv) {
    using namespace std::chrono;
    int marked_for_deletion = 0;
    std::unordered_map<std::string, std::vector<std::string>> filehashes;
    std::string algorithm = "SHA-256";  // Default set to SHA-256

    // Argument processing: Check if -md5 or -sha256 flag is provided
    if (argc > 1 && std::string(argv[1]) == "-md5") {
        algorithm = "MD5";
        argc--;
        argv++;
    } else if (argc > 1 && (std::string(argv[1]) == "-sha256" || std::string(argv[1]) == "SHA-256")) {
        algorithm = "SHA-256";
        argc--;
        argv++;
    } else if (argc > 1 && (std::string(argv[1]) == "-help" || std::string(argv[1]) == "--help")) {
        std::cout << "Usage: " << argv[0] << " [Options] <directory> [<directory> ...]\n";
        std::cout << "Options:\n";
        std::cout << "  -md5         Use MD5 hashing algorithm\n";
        std::cout << "  -sha256      Use SHA-256 hashing algorithm (default)\n";
        return 0;
    }

    // Check if at least one directory is specified
    if (argc < 2) {
        std::cerr << "Error: At least one directory must be specified.\n";
        std::cerr << "Usage: " << argv[0] << " [Options] <directory> [<directory> ...]\n";
        return 1;
    }

    std::cout << "Used Algo: " << algorithm << std::endl;

    // Initialize log file
    std::string logdate = getCurrentDateTime();
    std::string logfile = "log_" + logdate + ".txt";
    std::ofstream logFile(logfile);
    logFile << "Log for the duplicate deletion script\n";
    logFile << "Date: " << logdate << "\n";
    logFile << "Using algorithm: " << algorithm << "\n";
    logFile << "Directories:\n";
    for (int i = 1; i < argc; i++) {
        logFile << "- " << argv[i] << "\n";
    }
    logFile << "-------------------\n";

    // Count total number of files in the specified directories
    int total_files = 0;
    for (int i = 1; i < argc; i++) {
        if (!std::filesystem::exists(argv[i])) {
            std::cerr << "Directory not found: " << argv[i] << std::endl;
            continue;
        }
        for (const auto &entry : std::filesystem::recursive_directory_iterator(argv[i])) {
            if (entry.is_regular_file()) {
                total_files++;
            }
        }
    }

    // Select directories from which duplicates should be deleted
    std::cout << "Choose directories to delete duplicates from (comma separated, e.g. 1,3,4):\n";
    for (int i = 1; i < argc; i++) {
        std::cout << i << ") " << argv[i] << "\n";
    }
    std::string selection;
    std::getline(std::cin, selection);
    std::istringstream ss(selection);
    std::string token;
    std::vector<int> delete_indices;
    while (std::getline(ss, token, ',')) {
        try {
            delete_indices.push_back(std::stoi(token));
        } catch (const std::exception &e) {
            std::cerr << "Invalid input: " << token << std::endl;
        }
    }
    std::vector<std::string> delete_dirs;
    for (auto index : delete_indices) {
        if (index >= 1 && index < argc)
            delete_dirs.push_back(argv[index]);
    }

    // DRY run prompt (simulate deletion without actual file removal)
    std::string dry_run_input;
    std::cout << "Do you want to perform a DRY run (simulate deletion without actual file removal)? [Y/n]: ";
    std::getline(std::cin, dry_run_input);
    bool dry_run = true;
    if (!dry_run_input.empty() && (dry_run_input == "n" || dry_run_input == "N")) {
        dry_run = false;
    }

    // Manual deletion prompt if not in DRY run mode
    std::string manual_delete;
    if (!dry_run) {
        std::cout << "You are about to delete the files. Are you sure? [y/N]: ";
        std::string sure_delete;
        std::getline(std::cin, sure_delete);
        if (sure_delete.empty() || sure_delete == "n" || sure_delete == "N") {
            std::cout << "Aborted.\n";
            return 0;
        }
        std::cout << "Do you want to delete the files manually? [Y/n]: ";
        std::getline(std::cin, manual_delete);
        if (manual_delete.empty()) {
            manual_delete = "y";
        }
    } else {
        manual_delete = "dry";
    }

    int current_file = 0;
    auto start = steady_clock::now();

    // Iterate through all specified directories and calculate the hash for each file
    for (int i = 1; i < argc; i++) {
        if (!std::filesystem::exists(argv[i]))
            continue;
        for (const auto &entry : std::filesystem::recursive_directory_iterator(argv[i])) {
            if (entry.is_regular_file()) {
                std::string path = std::filesystem::absolute(entry.path()).string();
                std::string hash = getHash(path, algorithm);
                // Only valid hashes are stored
                if (!hash.empty()) {
                    filehashes[hash].push_back(path);
                }
                current_file++;
                int percent = (current_file * 100) / total_files;
                auto elapsed = duration_cast<seconds>(steady_clock::now() - start);
                int estimated_total = (elapsed.count() * total_files) / current_file;
                if (manual_delete == "dry") {
                    std::cout << "Calculating " << algorithm << " hashes: " 
                              << current_file << "/" << total_files
                              << " (" << percent << "%) Elapsed: " 
                              << formatDuration(elapsed.count())
                              << " Estimated Total: " 
                              << formatDuration(estimated_total) << "\r" << std::flush;
                }
            }
        }
    }
    std::cout << std::endl;

    // Process duplicates
    for (const auto &[hash, files] : filehashes) {
        if (files.size() > 1) {
            std::string duplicates;
            for (const auto &file : files) {
                duplicates += file + ", ";
            }
            if (!duplicates.empty())
                duplicates = duplicates.substr(0, duplicates.size() - 2); // Remove last comma

            // Create a list of files that are located in the deletion directories
            std::vector<std::string> files_to_delete;
            for (const auto &dir_to_delete : delete_dirs) {
                for (const auto &file : files) {
                    if (isPathInDirectory(file, dir_to_delete)) {
                        files_to_delete.push_back(file);
                    }
                }
            }

            // If no candidate in deletion directories is found, skip
            if (files_to_delete.empty()) {
                for (const auto &file : files) {
                    logFile << "Skipped " << file 
                            << " (Hash: " << hash 
                            << ", Duplicates: " << duplicates << ")\n";
                }
                continue;
            }

            // Manual deletion prompt: user explicitly selects which file to keep
            if (manual_delete == "y" || manual_delete == "Y") {
                std::cout << "\nFound duplicates with hash " << hash << " in selected directories:\n";
                for (size_t i = 0; i < files_to_delete.size(); i++) {
                    std::cout << i + 1 << ") " << files_to_delete[i] << "\n";
                }
                std::cout << "Please select the file number to KEEP (others will be deleted), or 0 to skip deletion: ";
                int keep_index;
                std::cin >> keep_index;
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                if (keep_index <= 0 || keep_index > (int)files_to_delete.size()) {
                    // If 0 or invalid input, skip deletion for this group
                    for (const auto &file : files_to_delete) {
                        logFile << "Skipped " << file 
                                << " (Hash: " << hash 
                                << ", Duplicates: " << duplicates << ")\n";
                    }
                } else {
                    // Delete all files except the one selected by the user
                    for (size_t i = 0; i < files_to_delete.size(); i++) {
                        if ((int)i == keep_index - 1) {
                            logFile << "Kept " << files_to_delete[i] 
                                    << " (Hash: " << hash 
                                    << ", Duplicates: " << duplicates << ")\n";
                            continue;
                        }
                        if (dry_run) {
                            logFile << "DRY run: Would delete " << files_to_delete[i] 
                                    << " (Hash: " << hash 
                                    << ", Duplicates: " << duplicates << ")\n";
                        } else {
                            try {
                                std::filesystem::remove(files_to_delete[i]);
                                logFile << "Deleted " << files_to_delete[i] 
                                        << " (Hash: " << hash 
                                        << ", Duplicates: " << duplicates << ")\n";
                                marked_for_deletion++;
                            } catch (const std::filesystem::filesystem_error &e) {
                                std::cerr << "Error deleting file: " << files_to_delete[i] 
                                          << " - " << e.what() << std::endl;
                                logFile << "Failed to delete " << files_to_delete[i] 
                                        << " - " << e.what() << "\n";
                            }
                        }
                    }
                }
            } else {
                // Automatic mode: if all duplicates are in the deletion directories,
                // keep one file and delete the rest.
                if (files_to_delete.size() == files.size() && !files_to_delete.empty()) {
                    // Log the kept file before deletion.
                    logFile << "Kept " << files_to_delete[0] 
                            << " (Hash: " << hash 
                            << ", Duplicates: " << duplicates << ")\n";
                    files_to_delete.erase(files_to_delete.begin());
                }
                for (const auto &file_to_delete : files_to_delete) {
                    if (dry_run) {
                        logFile << "DRY run: Would delete " << file_to_delete 
                                << " (Hash: " << hash 
                                << ", Duplicates: " << duplicates << ")\n";
                    } else {
                        try {
                            std::filesystem::remove(file_to_delete);
                            logFile << "Deleted " << file_to_delete 
                                    << " (Hash: " << hash 
                                    << ", Duplicates: " << duplicates << ")\n";
                            marked_for_deletion++;
                        } catch (const std::filesystem::filesystem_error &e) {
                            std::cerr << "Error deleting file: " << file_to_delete 
                                      << " - " << e.what() << std::endl;
                            logFile << "Failed to delete " << file_to_delete 
                                    << " - " << e.what() << "\n";
                        }
                    }
                }
            }
        }
    }

    std::cout << marked_for_deletion << " Dup Files processed.\nDone. Check " 
              << logfile << " for details.\n";
    logFile.close();

    std::string open_logfile;
    std::cout << "Do you want to open the logfile with nano? [Y/n]: ";
    std::getline(std::cin, open_logfile);
    if (open_logfile.empty() || open_logfile == "y" || open_logfile == "Y") {
        std::string command = "nano " + logfile;
        system(command.c_str());
    }
    
    return 0;
}
