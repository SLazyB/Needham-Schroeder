//
//  c1.cpp
//  First to obtain session key
//
//  Created by Cavell on 10/7/18.
//
//

#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <vector>
#include <bitset>
#include <time.h>
#include <math.h>
#include <unistd.h>

using namespace std;
//Server side
class S_DES{
public:
    S_DES(string k): key(k) {sub_gen(k);}
    string Encrypt(string input){
        vector<bitset<8> > s_b;
        vector<string> conv;
        vector<string> end_crypt;
        for(int i = 0; i < input.size(); i++){
            s_b.push_back(bitset<8>(input.c_str()[i]));
        }
        for(int j = 0; j < s_b.size(); j++){
            conv.push_back(Permutation(s_b[j]));
        }
        
        //Main Encryption
        string tmp = "";
        string tmp1_l = "";
        string tmp1_r = "";
        string tmp2_l = "";
        string tmp2_r = "";
        string tmp3 = "";
        string fk1 = "";
        string fk2 = "";
        for(int a = 0; a < conv.size(); a++){   //Loops through vector and stores all encrypted text to end_crypt
            tmp = conv[a];
            
            //Splitting the original 8-bit set
            tmp1_l = tmp.substr(0,4);
            tmp1_r = tmp.substr(4,4);
            tmp2_l = tmp1_r;
            
            //First round
            fk1 = F(tmp1_r, key1);
            tmp2_r = (bitset<4>(tmp1_l) ^ bitset<4>(fk1)).to_string();
            
            //Second round
            fk2 = F(tmp2_r, key2);
            tmp3 = (bitset<4>(tmp2_l) ^ bitset<4>(fk2)).to_string();
            
            tmp3.append(tmp2_r);
            end_crypt.push_back(invPermutation(tmp3));
            
        }
        //Creates new encrypted string
        string output = "";
        for(int m = 0; m < end_crypt.size(); m++){
            output.push_back(char(bitset<8>(end_crypt[m]).to_ulong()));
        }
        
        return output;
    }
    string Decrypt(string input){
        vector<bitset<8> > s_b;
        vector<string> conv;
        vector<string> end_crypt;
        for(int i = 0; i < input.size(); i++){
            s_b.push_back(bitset<8>(input.c_str()[i]));
        }
        for(int j = 0; j < s_b.size(); j++){
            conv.push_back(Permutation(s_b[j]));
        }
        
        //Main Decrypt
        string tmp = "";
        string tmp1_l = "";
        string tmp1_r = "";
        string tmp2_l = "";
        string tmp2_r = "";
        string tmp3 = "";
        string fk1 = "";
        string fk2 = "";
        
        for(int a = 0; a < conv.size(); a++){   //Loops through vector and stores all encrypted text to end_crypt
            tmp = conv[a];
            
            //Splitting the original 8-bit set
            tmp1_l = tmp.substr(0,4);
            tmp1_r = tmp.substr(4,4);
            tmp2_l = tmp1_r;
            
            //First Round
            fk1 = F(tmp1_r, key2);
            tmp2_r = (bitset<4>(tmp1_l) ^ bitset<4>(fk1)).to_string();
            
            //Second round
            fk2 = F(tmp2_r, key1);
            tmp3 = (bitset<4>(tmp2_l) ^ bitset<4>(fk2)).to_string();
            
            
            tmp3.append(tmp2_r);
            end_crypt.push_back(invPermutation(tmp3));
            
        }
        
        //Creating new decrypted string
        string output = "";
        for(int m = 0; m < end_crypt.size(); m++){
            output.push_back(char(bitset<8>(end_crypt[m]).to_ulong()));
        }
        
        return output;
    }
    
private:
    string Permutation(bitset<8> input){    //Initial permutation
        string tmp = input.to_string();
        string out;
        out.push_back(tmp[1]);
        out.push_back(tmp[5]);
        out.push_back(tmp[2]);
        out.push_back(tmp[0]);
        out.push_back(tmp[3]);
        out.push_back(tmp[7]);
        out.push_back(tmp[4]);
        out.push_back(tmp[6]);
        return out;
    }
    string invPermutation(string input){    //Ending permutation
        string tmp = input;
        string out;
        out.push_back(tmp[3]);
        out.push_back(tmp[0]);
        out.push_back(tmp[2]);
        out.push_back(tmp[4]);
        out.push_back(tmp[6]);
        out.push_back(tmp[1]);
        out.push_back(tmp[7]);
        out.push_back(tmp[5]);
        return out;
    }
    string P10(string key){     //10-bit Permutation
        string tmp = key;
        string out;
        out.push_back(tmp[2]);
        out.push_back(tmp[4]);
        out.push_back(tmp[1]);
        out.push_back(tmp[6]);
        out.push_back(tmp[3]);
        out.push_back(tmp[9]);
        out.push_back(tmp[0]);
        out.push_back(tmp[8]);
        out.push_back(tmp[7]);
        out.push_back(tmp[5]);
        return out;
        
    }
    string P8(string kp){   //8-bit Permutation
        string tmp = kp;
        string out;
        out.push_back(tmp[5]);
        out.push_back(tmp[2]);
        out.push_back(tmp[6]);
        out.push_back(tmp[3]);
        out.push_back(tmp[7]);
        out.push_back(tmp[4]);
        out.push_back(tmp[9]);
        out.push_back(tmp[8]);
        return out;
        
    }
    string P4(string kp){   //4-bit Permutation
        string out;
        out.push_back(kp[1]);
        out.push_back(kp[3]);
        out.push_back(kp[2]);
        out.push_back(kp[0]);
        return out;
    }
    string lshift(string kp){   //Left rolling by 1-bit
        string kp_s = kp.substr(1,4);
        kp_s.push_back(kp[0]);
        return kp_s;
    }
    string Expansion(string input){     //4-bit to 8-bit expansion
        string out;
        out.push_back(input[3]);
        out.push_back(input[0]);
        out.push_back(input[1]);
        out.push_back(input[2]);
        out.push_back(input[1]);
        out.push_back(input[2]);
        out.push_back(input[3]);
        out.push_back(input[0]);
        return out;
    }
    void sub_gen(string key){   //Creates the two parts of the key
        string kp = P10(key);
        string k1_l = lshift(kp.substr(0,5));
        string k1_r = lshift(kp.substr(5,5));
        key1 = P8((k1_l + k1_r));
        
        string k2_l = lshift(k1_l);
        string k2_r = lshift(k1_r);
        key2 = P8((k2_l + k2_r));
    }
    string F(string input, string kp){  //F function
        string s0[4][4] = { {"01","00","11","10"}, {"11","10","01","00"}, {"00","10","01","11"}, {"11","01","11","10"}};
        string s1[4][4] = { {"00","01","10","11"}, {"10","00","01","11"}, {"11","00","01","00"}, {"10","01","00","11"}};
        
        string i_e = Expansion(input);
        string x_o = (bitset<8>(i_e) ^ bitset<8>(kp)).to_string();
        string x_ol = x_o.substr(0,4);
        string x_or = x_o.substr(4,4);
        string sl_0;
        sl_0.push_back(x_ol[0]);
        sl_0.push_back(x_ol[3]);
        string sr_0;
        sr_0.push_back(x_ol[1]);
        sr_0.push_back(x_ol[2]);
        string sl_1;
        sl_1.push_back(x_or[0]);
        sl_1.push_back(x_or[3]);
        string sr_1;
        sr_1.push_back(x_or[1]);
        sr_1.push_back(x_or[2]);
        
        string s_o0 = s0[int(bitset<2>(sl_0).to_ulong())][int(bitset<2>(sr_0).to_ulong())];
        string s_o1 = s1[int(bitset<2>(sl_1).to_ulong())][int(bitset<2>(sr_1).to_ulong())];
        string out = P4(s_o0.append(s_o1));
        return out;
    }
    
    //Stores key for current encryption/decryption process
    string key;
    string key1;
    string key2;
};

string gen_nonce(){
    string out = "";
    for(int i = 0; i < 10; i++){
        out.push_back(char(rand() % 128));
    }
    return out;
}

int getprime(){
    bool done = false;
    int test;
    int i = 0;
    int w = 0;
    while (!done) {
        test = rand();
        if(test == 2 || test == 3){
            done = true;
        }
        else if(test % 2 == 0 || test % 3 == 0){
            continue;
        }
        else{
            i = 5;
            w = 2;
            while (i * i <= test){
                if(test % i == 0){
                    break;
                }
                i += w;
                w = 6 - w;
            }
            if(i * i > test){
                done = true;
            }
        }
    }
    return test;
}

int diffie(int p, int a, int r){
    long long int calc = pow(r, a);
    int out = calc % p;
    return out;
}

int main(int argc, char *argv[])
{
    //for the server, we only need to specify a port number
    srand(time(NULL));
    string s_ID = "A";
    int p = 97;
    int g = 7;
    int s1 = rand() % 9 + 1;
    
    //grab the IP address and port number, statically allocated
    char *serverIp = "127.0.0.1"; int port = 12345;
    
    //create a message buffer
    char msg[1500];
    
    //setup a socket and connection tools
    struct hostent* host = gethostbyname(serverIp);
    sockaddr_in sendSockAddr;
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr));
    sendSockAddr.sin_family = AF_INET;
    sendSockAddr.sin_addr.s_addr =
    inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    //try to connect...
    bool conn = false;
    while (!conn) {
        int status = connect(clientSd,
                             (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
        if(status >= 0)
        {
            conn = true;
        }

    }
    //Send messages for diffie and completing
    
    //Start of diffie
    int m1 = long(pow(g, s1)) % p;  //Needs to be sent
    int r = 0;
    int bytesRead, bytesWritten = 0;
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);

    //Sending and receiving mod results
    string data = "A";
    memset(&msg, 0, sizeof(msg));//clear the buffer
    strcpy(msg, data.c_str());
    bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
    
    data = to_string(m1);
    memset(&msg, 0, sizeof(msg));//clear the buffer
    strcpy(msg, data.c_str());
    bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
    cout << "Awaiting server response..." << endl;
    memset(&msg, 0, sizeof(msg));//clear the buffer
    
    bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
    cout << "Server: " << msg << endl;
    
    r = atoi(msg);
    int s2 = diffie(p, s1, r);
    data = "exit";
    memset(&msg, 0, sizeof(msg));//clear the buffer
    strcpy(msg, data.c_str());
    send(clientSd, (char*)&msg, strlen(msg), 0);
    
    //End initial server connection
    close(clientSd);
    //Obtained Kas
    
    //sleep(5);
    //Main Needham Section - TBD
    
    return 0;
}