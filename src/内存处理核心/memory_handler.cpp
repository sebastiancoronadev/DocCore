#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <string>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <unordered_map>
#include <iomanip>
#include <sstream>

class MemoryBufferHandler {
private:
    std::vector<uint8_t> buffer;
    std::string filePath;
    size_t originalSize;
    std::chrono::high_resolution_clock::time_point startTime;

public:
    MemoryBufferHandler(const std::string& path) : filePath(path) {
        startTime = std::chrono::high_resolution_clock::now();
        
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "{\"error\": \"Cannot open file: " << path << "\"}" << std::endl;
            exit(1);
        }
        
        originalSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        buffer.resize(originalSize);
        file.read(reinterpret_cast<char*>(buffer.data()), originalSize);
        file.close();
    }

    void stripMetadata() {
        size_t bytesStripped = 0;
        std::vector<uint8_t> cleanedBuffer;
        cleanedBuffer.reserve(buffer.size());
        
        bool inMetadata = false;
        int metadataDepth = 0;
        bool inString = false;
        
        const char* metadataKeys[] = {
            "/Title", "/Author", "/Subject", "/Creator", 
            "/Producer", "/Keywords", "/CreationDate", "/ModDate",
            "/Company", "/Manager", "/Category", "/Comments"
        };
        const int numKeys = sizeof(metadataKeys) / sizeof(metadataKeys[0]);
        
        for (size_t i = 0; i < buffer.size(); ++i) {
            if (!inMetadata) {
                for (int k = 0; k < numKeys; ++k) {
                    size_t keyLen = strlen(metadataKeys[k]);
                    if (i + keyLen < buffer.size()) {
                        if (memcmp(&buffer[i], metadataKeys[k], keyLen) == 0) {
                            inMetadata = true;
                            inString = true;
                            metadataDepth = 1;
                            i += keyLen - 1;
                            bytesStripped += keyLen;
                            goto nextByte;
                        }
                    }
                }
            }
            
            if (inMetadata && inString) {
                if (buffer[i] == '(') {
                    metadataDepth++;
                } else if (buffer[i] == ')') {
                    metadataDepth--;
                    if (metadataDepth == 0) {
                        inMetadata = false;
                        inString = false;
                        bytesStripped++;
                        goto nextByte;
                    }
                } else if (buffer[i] == '\\') {
                    bytesStripped++;
                    i++;
                    bytesStripped++;
                    goto nextByte;
                }
                bytesStripped++;
                goto nextByte;
            }
            
            if (!inMetadata) {
                cleanedBuffer.push_back(buffer[i]);
            } else {
                bytesStripped++;
            }
            
            nextByte:;
        }
        
        buffer = std::move(cleanedBuffer);
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
        
        std::cout << "{" << std::endl;
        std::cout << "  \"status\": \"success\"," << std::endl;
        std::cout << "  \"operation\": \"metadata_strip\"," << std::endl;
        std::cout << "  \"original_size\": " << originalSize << "," << std::endl;
        std::cout << "  \"cleaned_size\": " << buffer.size() << "," << std::endl;
        std::cout << "  \"bytes_removed\": " << bytesStripped << "," << std::endl;
        std::cout << "  \"reduction_percent\": " << std::fixed << std::setprecision(2) 
                  << (100.0 * bytesStripped / originalSize) << "," << std::endl;
        std::cout << "  \"processing_time_us\": " << duration.count() << std::endl;
        std::cout << "}" << std::endl;
    }

    void calculateMemoryEntropy() {
        std::unordered_map<uint8_t, size_t> frequencies;
        
        for (auto byte : buffer) {
            frequencies[byte]++;
        }
        
        double entropy = 0.0;
        double size = buffer.size();
        
        for (const auto& [byte, freq] : frequencies) {
            double probability = freq / size;
            entropy -= probability * std::log2(probability);
        }
        
        double normalizedEntropy = entropy / 8.0;
        std::string riskLevel = normalizedEntropy > 0.85 ? "HIGH" : 
                                normalizedEntropy > 0.70 ? "MEDIUM" : "LOW";
        
        std::cout << "{" << std::endl;
        std::cout << "  \"entropy_raw\": " << entropy << "," << std::endl;
        std::cout << "  \"entropy_normalized\": " << normalizedEntropy << "," << std::endl;
        std::cout << "  \"risk_level\": \"" << riskLevel << "\"," << std::endl;
        std::cout << "  \"unique_bytes\": " << frequencies.size() << "," << std::endl;
        std::cout << "  \"most_frequent_byte\": \"0x" << std::hex 
                  << (int)(std::max_element(frequencies.begin(), frequencies.end(),
                     [](const auto& a, const auto& b) { return a.second < b.second; })->first)
                  << "\"" << std::endl;
        std::cout << "}" << std::endl;
    }

    void extractEmbeddedPayloads() {
        std::vector<size_t> peOffsets = findPattern({0x4D, 0x5A});
        std::vector<size_t> elfOffsets = findPattern({0x7F, 0x45, 0x4C, 0x46});
        std::vector<size_t> machOOffsets = findPattern({0xCA, 0xFE, 0xBA, 0xBE});
        std::vector<size_t> shellcodeOffsets = findHighEntropyRegions(256, 0.90);
        
        std::cout << "{" << std::endl;
        std::cout << "  \"pe_signatures\": " << peOffsets.size() << "," << std::endl;
        std::cout << "  \"elf_signatures\": " << elfOffsets.size() << "," << std::endl;
        std::cout << "  \"macho_signatures\": " << machOOffsets.size() << "," << std::endl;
        std::cout << "  \"high_entropy_regions\": " << shellcodeOffsets.size() << "," << std::endl;
        std::cout << "  \"total_payloads_found\": " 
                  << (peOffsets.size() + elfOffsets.size() + machOOffsets.size() + shellcodeOffsets.size()) << std::endl;
        std::cout << "}" << std::endl;
    }

private:
    std::vector<size_t> findPattern(const std::vector<uint8_t>& pattern) {
        std::vector<size_t> offsets;
        
        if (pattern.empty() || buffer.size() < pattern.size()) {
            return offsets;
        }
        
        for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); ++j) {
                if (buffer[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                offsets.push_back(i);
                i += pattern.size() - 1;
            }
        }
        
        return offsets;
    }

    std::vector<size_t> findHighEntropyRegions(size_t windowSize, double threshold) {
        std::vector<size_t> offsets;
        
        if (buffer.size() < windowSize) {
            return offsets;
        }
        
        for (size_t i = 0; i <= buffer.size() - windowSize; i += windowSize / 2) {
            double entropy = calculateLocalEntropy(i, windowSize);
            if (entropy > threshold) {
                offsets.push_back(i);
                i += windowSize;
            }
        }
        
        return offsets;
    }

    double calculateLocalEntropy(size_t start, size_t length) {
        if (start + length > buffer.size()) {
            return 0.0;
        }
        
        std::unordered_map<uint8_t, size_t> localFreq;
        
        for (size_t i = start; i < start + length; ++i) {
            localFreq[buffer[i]]++;
        }
        
        double entropy = 0.0;
        for (const auto& [byte, freq] : localFreq) {
            double p = static_cast<double>(freq) / length;
            if (p > 0) {
                entropy -= p * std::log2(p);
            }
        }
        
        return entropy / 8.0;
    }
};

void printUsage() {
    std::cout << "{" << std::endl;
    std::cout << "  \"usage\": \"memory_handler --file <path> [--strip-metadata] [--entropy] [--extract-payloads]\"," << std::endl;
    std::cout << "  \"operations\": [" << std::endl;
    std::cout << "    \"--strip-metadata: Remove PDF/Office metadata from memory buffer\"," << std::endl;
    std::cout << "    \"--entropy: Calculate Shannon entropy of memory buffer\"," << std::endl;
    std::cout << "    \"--extract-payloads: Find embedded executables and shellcode\"" << std::endl;
    std::cout << "  ]" << std::endl;
    std::cout << "}" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage();
        return 1;
    }
    
    std::string filePath;
    bool stripMetadata = false;
    bool calculateEntropy = false;
    bool extractPayloads = false;
    
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            filePath = argv[++i];
        } else if (std::strcmp(argv[i], "--strip-metadata") == 0) {
            stripMetadata = true;
        } else if (std::strcmp(argv[i], "--entropy") == 0) {
            calculateEntropy = true;
        } else if (std::strcmp(argv[i], "--extract-payloads") == 0) {
            extractPayloads = true;
        }
    }
    
    if (filePath.empty()) {
        std::cerr << "{\"error\": \"No file specified. Use --file <path>\"}" << std::endl;
        return 1;
    }
    
    try {
        MemoryBufferHandler handler(filePath);
        
        if (stripMetadata) {
            handler.stripMetadata();
        }
        
        if (calculateEntropy) {
            handler.calculateMemoryEntropy();
        }
        
        if (extractPayloads) {
            handler.extractEmbeddedPayloads();
        }
        
        if (!stripMetadata && !calculateEntropy && !extractPayloads) {
            printUsage();
        }
        
    } catch (const std::exception& e) {
        std::cerr << "{\"error\": \"" << e.what() << "\"}" << std::endl;
        return 1;
    }
    
    return 0;
}