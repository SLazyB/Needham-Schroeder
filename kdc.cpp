//
//  kdc.cpp
//  Distributes keys to clients
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
#include <map>

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
    int p = 97;
    int g = 7;
    int s1 = rand() % 9 + 1;
    map<string, int> sym_key;       //Keep track of symmetric key
    cout << getprime() << endl;
    //grab the port number
    int port = 12345;
    //buffer to send and receive messages with
    char msg[1500];
    
    //setup a socket and connection tools
    sockaddr_in servAddr;
    bzero((char*)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);
    
    //open stream oriented socket with internet address
    //also keep track of the socket descriptor
    int serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSd < 0)
    {
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }
    //bind the socket to its local address
    int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr,
                          sizeof(servAddr));
    if(bindStatus < 0)
    {
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    //listen for up to 5 requests at a time
    listen(serverSd, 5);
    //receive a request from client using accept
    //we need a new address to connect with the client
    sockaddr_in newSockAddr;
    socklen_t newSockAddrSize = sizeof(newSockAddr);
    //accept, create a new socket descriptor to
    //handle the new connection with client
    int newSd;
    
    //lets keep track of the session time
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);
    //also keep track of the amount of data sent as well
    int bytesRead, bytesWritten = 0;
    
    //Start of diffie
    int m1 = long(pow(g, s1)) % p;  //Needs to be sent
    int s2_a, s2_b;     //Symmetric keys
    
    //Bob's Run
    newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
    cout << "Connected with client!" << endl;
    
    //receive a message from the client (listen)
    
    cout << "Awaiting client number" << endl;
    memset(&msg, 0, sizeof(msg));//clear the buffer
    bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);
    s2_b = diffie(p, s1, atoi(msg));
    sym_key["B"] = s2_b;
    cout << "Client: " << msg << endl;
    cout << ">";
    string data = to_string(m1);
    memset(&msg, 0, sizeof(msg)); //clear the buffer
    strcpy(msg, data.c_str());
    //send the message to client
    bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);

    close(newSd);
    S_DES *sb = new S_DES(bitset<10>(to_string(sym_key["B"])).to_string());
    //Alice's Run
    newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
    
    cout << "Awaiting client number" << endl;
    memset(&msg, 0, sizeof(msg));//clear the buffer
    bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);

    s2_a = diffie(p, s1, atoi(msg));
    sym_key["A"] = s2_a;
    cout << "Client: " << msg << endl;
    cout << ">";
    data = to_string(m1);
    memset(&msg, 0, sizeof(msg)); //clear the buffer
    strcpy(msg, data.c_str());
    //send the message to client
    bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
    
    S_DES *sa = new S_DES(bitset<10>(to_string(sym_key["A"])).to_string());
    
    //Main Needham-Schroeder
    while (1){
        //receive a message from the client (listen)
        cout << "Awaiting client response..." << endl;
        memset(&msg, 0, sizeof(msg));//clear the buffer
        bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);
        if(!strcmp(msg, "A")){
            break;
            
        }
        else if(!strcmp(msg, "exit")){
            cout << "Client has quit the session" << endl;
            break;
        }
        
    }
    
    //we need to close the socket descriptors after we're all done
    gettimeofday(&end1, NULL);
    close(newSd);
    close(serverSd);
    cout << "********Session********" << endl;
    cout << "Bytes written: " << bytesWritten << " Bytes read: " << bytesRead << endl;
    cout << "Elapsed time: " << (end1.tv_sec - start1.tv_sec)
    << " secs" << endl;
    cout << "Connection closed..." << endl;
    return 0;
}