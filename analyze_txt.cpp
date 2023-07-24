#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <vector>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

// Function to convert a hexadecimal string to decimal
int hex_to_decimal(const std::string &hex_str)
{
    int result;
    std::stringstream ss;
    ss << std::hex << hex_str;
    ss >> result;
    return result;
}

// Function to convert a hexadecimal string to binary
std::vector<unsigned char> hex_to_binary(const std::string &hex)
{
    std::vector<unsigned char> binary;
    binary.reserve(hex.length() / 2);

    // Iterate through the hexadecimal string two characters at a time
    for (std::size_t i = 0; i < hex.length(); i += 2)
    {
        unsigned int byte;
        // Extract two characters from the string and convert them to an unsigned integer in hexadecimal format
        std::istringstream(hex.substr(i, 2)) >> std::hex >> byte;
        // Convert the unsigned integer to an unsigned character and store it in the binary vector
        binary.push_back(static_cast<unsigned char>(byte));
    }

    return binary;
}

// Process data from hexadecimal to binary and store as DER file
void save_certificate_DER(const std::string &hex_string, const std::string &folder_name)
{
    // Remove spaces, "0A 3B 56.. " to "0A3B56.."
    std::string cleaned_hex_string = hex_string;
    cleaned_hex_string.erase(std::remove_if(cleaned_hex_string.begin(), cleaned_hex_string.end(), ::isspace), cleaned_hex_string.end());

    // Convert hexadecimal string to binary data
    std::vector<unsigned char> certificate_data = hex_to_binary(cleaned_hex_string);

    // Check if certificate file already exists
    std::string file_name = folder_name + "/certificate.der";
    int counter = 2;
    while (fs::exists(file_name))
    {
        std::stringstream ss;
        ss << folder_name << "/certificate_" << counter << ".der";
        file_name = ss.str();
        counter++;
    }

    // Save certificate data as a DER file in the specified folder
    std::ofstream outfile(file_name, std::ios::binary);
    outfile.write(reinterpret_cast<char *>(&certificate_data[0]), certificate_data.size());
    outfile.close();
}

// Function to split a string based on a delimiter
std::vector<std::string> split_string(const std::string &input, char delimiter)
{
    std::vector<std::string> tokens;
    std::istringstream ss(input);
    std::string token;
    while (std::getline(ss, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

// Parse certificate data and save as DER files
void parse_certis(std::string &certis, std::string &address_port)
{
    // Create a folder for storing certificates based on the address and port
    std::string folder_name = "certificates/" + address_port;
    int folder_counter = 2;
    while (fs::exists(folder_name))
    {
        folder_name = "certificates/" + address_port + "_" + std::to_string(folder_counter);
        folder_counter++;
    }
    fs::create_directory(folder_name);

    while (!certis.empty())
    {
        // Extract the length of the current certificate
        std::string certi_length_str = certis.substr(0, 2) + certis.substr(3, 2) + certis.substr(6, 2);
        int certi_length = hex_to_decimal(certi_length_str);
        certis = certis.substr(9);

        // Extract the hexadecimal representation of the certificate
        std::string certi_str = certis.substr(0, 3 * certi_length);

        // Save the certificate data as a DER file in the created folder
        save_certificate_DER(certi_str, folder_name);

        // Move to the next certificate in the input string
        certis = certis.substr(3 * certi_length);
    }
}

int main()
{
    // Open the input file containing certificate data
    std::ifstream file("1.txt");
    if (!file.is_open())
    {
        std::cout << "Error opening file!" << std::endl;
        return 1;
    }

    std::string line;
    std::string certis; // Variable to store certificates

    // Create a folder to store certificates if it doesn't exist
    if (!fs::exists("certificates"))
    {
        fs::create_directory("certificates");
    }

    // Read the input file line by line and process the certificate data
    while (std::getline(file, line))
    {
        // Split the line using '/' as the delimiter
        std::vector<std::string> parts = split_string(line, '/');

        // Skip lines that don't have the expected format
        if (parts.size() != 2 || parts[0].empty() || parts[0] == "00 00 00 00 00 00 ")
        {
            continue;
        }

        // Check if the line matches the server hello pattern
        std::regex hello_pattern("^16 .. .. .. .. 02 .*");
        if (std::regex_match(parts[0], hello_pattern))
        {
            // Extract the length of the server hello payload
            std::string hello_length_str = parts[0].substr(9, 2) + parts[0].substr(12, 2);
            int hello_length = hex_to_decimal(hello_length_str);

            // Extract the certificate data
            std::string certis = parts[0].substr(15 + 3 * hello_length);

            // Check if it is a certification field
            std::regex cert_pattern("^16 .. .. .. .. 0B .*");
            if (std::regex_match(certis, cert_pattern))
            {
                // Remove "16 .. .. .. .. 0B .. .. .. "
                certis = certis.substr(27);

                // Total length of certifications
                std::string certis_total_length_str = certis.substr(0, 2) + certis.substr(3, 2) + certis.substr(6, 2);
                const int certis_total_length = hex_to_decimal(certis_total_length_str);

                // Remove total length string ".. .. .. "
                certis = certis.substr(9);

                int unread_certis_length = certis_total_length - (certis.size() / 3);

                // Read additional lines to complete the certificate data if necessary
                while (unread_certis_length > 0)
                {
                    std::getline(file, line);
                    std::vector<std::string> parts = split_string(line, '/');
                    if (unread_certis_length > (parts[0].size() / 3))
                    {
                        certis += parts[0];
                        unread_certis_length -= (parts[0].size() / 3);
                    }
                    else
                    {
                        certis += parts[0].substr(0, unread_certis_length * 3);
                        unread_certis_length = 0;
                    }
                }

                // Certis now completed with form (certi1 length + certi1 + certi2 length + certi2 ...)
                // Parse certifications and save them as DER files separately
                parse_certis(certis, parts[1]);
            }
            else
            {
                // Certification match failed, could be Change Cipher Spec
                continue;
            }
        }
        else
        {
            // Unrecognized line, skip
            continue;
        }
    }

    file.close();
    return 0;
}
