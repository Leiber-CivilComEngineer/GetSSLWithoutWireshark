#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace fs = std::filesystem;
using namespace std;

// Function to convert a hexadecimal string to binary
vector<unsigned char> hex_to_binary(const string &cleaned_hex_string)
{
    vector<unsigned char> binary;
    binary.reserve(cleaned_hex_string.length() / 2);

    // Iterate through the hexadecimal string two characters at a time
    for (size_t i = 0; i < cleaned_hex_string.length(); i += 2)
    {
        unsigned int byte;
        // Extract two characters from the string and convert them to an unsigned integer in hexadecimal format
        istringstream(cleaned_hex_string.substr(i, 2)) >> hex >> byte;
        // Convert the unsigned integer to an unsigned character and store it in the binary vector
        binary.push_back(static_cast<unsigned char>(byte));
    }
    return binary;
}

// Function to convert a hexadecimal string to decimal
int hex_to_decimal(const string &hex_str)
{
    int result;
    stringstream ss;
    ss << hex << hex_str;
    ss >> result;
    return result;
}

// Function to split a string based on a delimiter
vector<string> split_string(const string &input, char delimiter)
{
    vector<string> tokens;
    istringstream ss(input);
    string token;
    while (getline(ss, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

// Check if a file exists
bool fileExists(const string &filename)
{
    ifstream file(filename);
    return file.good();
}

// Convert payload data to a hexadecimal string
string payload_to_hex(const u_char *data, int data_len)
{
    ostringstream hex_stream;

    // Loop through each byte in the data
    for (int i = 0; i < data_len; i++)
    {
        // Convert the byte to its hexadecimal representation
        // using hex and set the width to 2 characters with
        // leading zeros using setw and setfill
        hex_stream << hex << setw(2) << setfill('0') << uppercase << static_cast<int>(data[i]) << " ";
    }

    return hex_stream.str();
}

// Process packet in pcap file to extract SSL payload and write to file
void process_packet(const u_char *packet, int packet_len, string buffer_file_name)
{
    // Extract Ethernet header
    struct ether_header *ethernet_header = (struct ether_header *)(packet);
    int ethernet_header_len = sizeof(struct ether_header);

    // Check if it's an IP packet
    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    // Extract IP header
    struct ip *ip_header = (struct ip *)(packet + ethernet_header_len);
    int ip_header_len = ip_header->ip_hl * 4;

    // Check if it's a TCP packet
    if (ip_header->ip_p != IPPROTO_TCP)
    {
        return;
    }

    // Extract TCP header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ethernet_header_len + ip_header_len);
    int tcp_header_len = tcp_header->th_off * 4;

    // Check if it's a SSL (HTTPS) packet (assuming source port 443)
    if (ntohs(tcp_header->th_sport) != 443)
    {
        return;
    }

    // Extract source IP and port
    char source_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
    uint16_t source_port = ntohs(tcp_header->th_sport);

    // Extract SSL payload (TCP data)
    const u_char *ssl_payload = packet + ethernet_header_len + ip_header_len + tcp_header_len;
    int ssl_payload_len = packet_len - ethernet_header_len - ip_header_len - tcp_header_len;

    // Write to buffer file
    ofstream file_stream(buffer_file_name, ios::app);
    if (file_stream)
    {
        // Get the SSL payload in hexadecimal format
        string hex_payload = payload_to_hex(ssl_payload, ssl_payload_len);

        // Write the hexadecimal payload to the file
        file_stream << hex_payload << "/" << source_ip_str << ":" << source_port << endl;
    }
}

// Function to extract Common Name (CN) from the X509 certificate
string get_common_name_from_certificate(X509 *x509)
{
    string common_name;
    X509_NAME *subject_name = X509_get_subject_name(x509);
    if (subject_name)
    {
        int common_name_index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
        if (common_name_index != -1)
        {
            X509_NAME_ENTRY *common_name_entry = X509_NAME_get_entry(subject_name, common_name_index);
            if (common_name_entry)
            {
                ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
                unsigned char *common_name_data = ASN1_STRING_data(common_name_asn1);
                int common_name_length = ASN1_STRING_length(common_name_asn1);
                common_name = string(reinterpret_cast<char *>(common_name_data), common_name_length);
            }
        }
    }
    return common_name;
}

// Process data from hexadecimal to binary and store as PEM file
void save_certificate_PEM(const string &hex_string, const string &folder_name)
{
    // Remove spaces, "0A 3B 56.. " to "0A3B56.."
    string cleaned_hex_string = hex_string;
    cleaned_hex_string.erase(remove_if(cleaned_hex_string.begin(), cleaned_hex_string.end(), ::isspace), cleaned_hex_string.end());

    // Convert hexadecimal string to binary data
    vector<unsigned char> certificate_data = hex_to_binary(cleaned_hex_string);

    string pem_file_name;

    const unsigned char *certificate_pointer = &certificate_data[0];
    X509 *x509 = d2i_X509(NULL, &certificate_pointer, certificate_data.size());

    if (!x509)
    {
        cerr << "Certification load failed: " << hex_string << endl;
        return;
    }

    // Get CommonName
    string CN = get_common_name_from_certificate(x509);

    // Pem file path
    string pem_file_path = folder_name + "/" + CN + ".pem";

    FILE *pem_file = fopen(pem_file_path.c_str(), "wb");
    if (!pem_file)
    {
        cerr << "Failed to create PEM file." << endl;
        return;
    }

    // Write certificate to PEM file
    PEM_write_X509(pem_file, x509);
    fclose(pem_file);
    X509_free(x509);
}

// Parse certificates data within a SSL handshake
void parse_certis(string &certis, string &address_port)
{
    // Construct folder name for storing certificates based on the address and port
    string folder_name = "certificates/" + address_port;
    int folder_counter = 2;
    while (fileExists(folder_name))
    {
        folder_name = "certificates/" + address_port + "_" + to_string(folder_counter);
        folder_counter++;
    }

    // Create file if not exits
    fs::create_directory(folder_name);

    while (!certis.empty())
    {
        // Extract the length of the current certificate
        string certi_length_str = certis.substr(0, 2) + certis.substr(3, 2) + certis.substr(6, 2);
        int certi_length = hex_to_decimal(certi_length_str);
        certis = certis.substr(9);

        // Extract the hexadecimal representation of the certificate
        string certi_str = certis.substr(0, 3 * certi_length);

        // Save the certificate data as a DER file in the created folder
        save_certificate_PEM(certi_str, folder_name);

        // Move to the next certificate in the input string
        certis = certis.substr(3 * certi_length);
    }
}

// Analyze buffer.txt file
int analyze_buffer(string buffer_file_name)
{
    ifstream file(buffer_file_name);

    if (!file.is_open())
    {
        cerr << "Error opening file!" << endl;
        return 1;
    }

    string line;
    string certis; // Variable to store certificates

    // Create a folder to store certificates if it doesn't exist
    if (!fileExists("certificates"))
    {
        // Create certificates folder
        fs::create_directory("certificates");
    }
    else
    {
        // Delete, and then create certificates folder
        fs::remove_all("certificates");
        fs::create_directory("certificates");
    }

    while (getline(file, line))
    {
        // Split the line using '/' as the delimiter
        vector<string> parts = split_string(line, '/');

        // Skip lines that don't have the expected format
        if (parts.size() != 2 || parts[0].empty() || parts[0] == "00 00 00 00 00 00 ")
        {
            continue;
        }

        // Check if the line matches the server hello pattern
        if (parts[0][0] == '1' && parts[0][1] == '6' && parts[0][15] == '0' && parts[0][16] == '2')
        {
            // Extract the length of the server hello payload
            string hello_length_str = parts[0].substr(9, 2) + parts[0].substr(12, 2);
            int hello_length = hex_to_decimal(hello_length_str);

            // Extract the certificate data
            string certis = parts[0].substr(15 + 3 * hello_length);

            // Check if it is a certification field
            if (certis[0] == '1' && certis[1] == '6' && certis[15] == '0' && certis[16] == 'B')
            {
                // Remove "16 .. .. .. .. 0B .. .. .. "
                certis = certis.substr(27);

                // Total length of certifications
                string certis_total_length_str = certis.substr(0, 2) + certis.substr(3, 2) + certis.substr(6, 2);
                const int certis_total_length = hex_to_decimal(certis_total_length_str);

                // Remove total length string ".. .. .. "
                certis = certis.substr(9);

                int unread_certis_length = certis_total_length - (certis.size() / 3);

                // Read additional lines to complete the certificate data if necessary
                while (unread_certis_length > 0)
                {
                    getline(file, line);
                    vector<string> parts = split_string(line, '/');
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
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        cerr << "Usage: " << argv[0] << " <pcap_file>" << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_offline(argv[1], errbuf);
    if (!pcap_handle)
    {
        cerr << "Error opening pcap file: " << errbuf << endl;
        return 1;
    }

    // Check if buffer txt file exits
    string buffer_file_name = "buffer.txt";

    ifstream file_check(buffer_file_name);

    if (!file_check)
    {
        // Create file if not exits
        ofstream file_create(buffer_file_name);
        if (file_create)
        {
            cout << "Buffer file created " << buffer_file_name << endl;
            file_create.close();
        }
        else
        {
            cerr << "Buffer file not exist and could not be created: " << buffer_file_name << endl;
            return 1;
        }
    }
    else
    {
        // Buffer file already created, clean it up
        ofstream file_clear(buffer_file_name, ios::trunc);
        if (file_clear)
        {
            cout << "Buffer file exists and cleaned " << buffer_file_name << endl;
            file_clear.close();
        }
        else
        {
            cerr << "Buffer file exists but could not be cleaned : " << buffer_file_name << endl;
            return 1;
        }
    }

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(pcap_handle, &header)))
    {
        process_packet(packet, header.len, buffer_file_name);
    }

    pcap_close(pcap_handle);

    cout << "Buffer file write completed" << endl;

    // Parse buffer file
    analyze_buffer(buffer_file_name);
    cout << "Bnalyze complete" << endl;
    return 0;
}