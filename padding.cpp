#include <cstdlib>
#include <cstdio>
#include <cerrno>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <error.h>

#include "constants.h"

#include <string>
#include <vector>
#include <iostream>
#include <stack>
#include <algorithm>
#include <thread>
#include <cstring>
#include <iomanip>


/*
 * GW
 * Some functions and lines have been removed for github
 * Need to pass in compilation arguments 
 * -DCTFILE=\"x" -DORACLE=\"x" -DMODE=\"CTR\" -DATTACK=\"constants\"
 * -DCTFILE=\"x" -DORACLE=\"x" -DMODE=\"CBC\" -DATTACK=\"timing\"
 * */



int main(int argc, char * argv[])
{
    ssize_t bytes_read;
    unsigned char ctbuf[IVLEN + MACLEN + CTLEN] = { '\0' };
    unsigned char ptbuf[IVLEN + MACLEN + CTLEN] = { '\0' };

    // loop till we're done...
    size_t ctlen = bytes_read;
    bool done = false;
    std::vector<char> ptascii;
    bool lastblock=true;
    float padcutoff = 0.03;

    /*
     * Set up the letter frequency list
     * */
    // https://reusablesec.blogspot.com/2009/05/character-frequency-analysis-info.html
    unsigned char freqcharset[] = "aeorisn1tl2md0cp3hbuk45g9687yfwjvzxqASERBTMLNPOIDCHGKFJUW0.!Y*@V-ZQX_$#,/+?;^ %~=&`\\)][:<(>\"|{'}";
    std::vector<int> englishfreq;
    for (char a : freqcharset) {
        englishfreq.push_back(a);
    }

    // Fill the rest of the frequency table with extended printable chars
    for (int i=128; i<256 ; i++) {
        englishfreq.push_back(i);
    }

    bool cbc_mode;
    bool timing_attack;
    int cbc_decr;
    if (MODE=="CBC") {
        cbc_decr = 16;
        cbc_mode=1;
    }
    else {
        cbc_decr=0;
        cbc_mode=0;
    }

    if (ATTACK=="timing") {
        timing_attack = true;
    }
    else timing_attack = false;


    /* Start deciphering
     * */
    while (!done)
    {
        int padbyte;

        /*
         * Looking for the padding byte
         * */
        int xorwith = 0x1;
        ctbuf[ctlen-1-cbc_decr]=ctbuf[ctlen-1-cbc_decr]^xorwith;
        // search for the int we need to XOR with to make last bit=1

        if (!timing_attack) {
            while (query_oracle(ctbuf, ctlen, ifd, ofd)=='P') {
                ctbuf[ctlen-1-cbc_decr]=ctbuf[ctlen-1-cbc_decr]^xorwith; // undo the last XOR op
                xorwith++;
                ctbuf[ctlen-1-cbc_decr]=ctbuf[ctlen-1-cbc_decr]^xorwith;
            }
        }

        //https://www.geeksforgeeks.org/measure-execution-time-with-high-precision-in-c-c/
        else {
            while (1) {
                auto start = std::chrono::high_resolution_clock::now();
                query_oracle(ctbuf, ctlen, ifd, ofd);
                auto end = std::chrono::high_resolution_clock::now();
                double time_taken = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
                time_taken *= 1e-6;
                if (time_taken>padcutoff) {
                    // oracle probably returned M
                    break;
                }
                ctbuf[ctlen-1-cbc_decr]=ctbuf[ctlen-1-cbc_decr]^xorwith; // undo the last XOR op
                xorwith++;
                ctbuf[ctlen-1-cbc_decr]=ctbuf[ctlen-1-cbc_decr]^xorwith;
            }
        }

        // Now we know the padding byte
        padbyte = xorwith^0x1;
        ctbuf[ctlen-1-cbc_decr]=ctbuf[ctlen-1-cbc_decr]^xorwith; //undo

        /* DECIPHER ALL BLOCKS
         * */
        int prevxor=0;
        int desiredpad=padbyte+1;   // for first block
        int blocknum=0;
        int ptcharslb=0;    // num pt chars grabbed from last block


        // save the previous block
        unsigned char prev_ctbuf_block[16] = {'\0'};
        if (cbc_mode) {
            for (int k=0; k<16; k++) {
                prev_ctbuf_block[k] = ctbuf[ctlen-1-cbc_decr-k];
            }
        }

        while(!done) {
            int ptindex = ctlen-cbc_decr-desiredpad;        // index of the byte we want to decipher

            /* Alter all padding bytes to match desired fake padding (only for last block)
             * */
            if (lastblock) {
                for (int i=1; i<=padbyte; i++) {
                    ctbuf[ctlen-i-cbc_decr]^=prevxor;
                    ctbuf[ctlen-i-cbc_decr]^=(padbyte^desiredpad);
                }
                prevxor = (padbyte^desiredpad);
            }

            /* Alter all the non-padding bytes to match desired fake padding
             * */
            int start, vecind;
            if (blocknum==0) {
                vecind=0;
                start = padbyte+1;
            }
            else {
                vecind= ptcharslb;
                start = 1;
            }
            for (int i=start; i<desiredpad; i++) {
                if (desiredpad-i!=1) ctbuf[ctlen-i-cbc_decr]^=(desiredpad-1)^ptascii[vecind]; //undo prev
                ctbuf[ctlen-i-cbc_decr]^=ptascii[vecind]^desiredpad;
                vecind++;
            }

            std::vector<int>::iterator it = englishfreq.begin();
            xorwith = (*it)^desiredpad;
            ctbuf[ptindex]^=xorwith;

            if (!timing_attack) {
                while ( query_oracle(ctbuf, ctlen, ifd, ofd) =='P') {
                    ctbuf[ptindex]^=xorwith; // undo the last XOR op
                    it++;
                    if (it==englishfreq.end()) break;
                    xorwith=(*it)^desiredpad;
                    ctbuf[ptindex]^=xorwith;
                }
            }

            else {
                while (1) {
                    auto start = std::chrono::high_resolution_clock::now();
                    query_oracle(ctbuf, ctlen, ifd, ofd);
                    auto end = std::chrono::high_resolution_clock::now();
                    double time_taken = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
                    time_taken *= 1e-6;
                    if (time_taken>padcutoff) {
                        //oracle probably returned M
                        break;
                    }
                    ctbuf[ptindex]^=xorwith; // undo the last XOR op
                    it++;
                    if (it==englishfreq.end()) break;
                    xorwith=(*it)^desiredpad;
                    ctbuf[ptindex]^=xorwith;
                }
            }


            ctbuf[ptindex]^=xorwith; //undo

            // now we know xorwith val for the plaintext byte
            int ptbyte = xorwith^desiredpad;
            ptascii.push_back(ptbyte);

            desiredpad++;
            if (desiredpad==17) {
                lastblock= false;
                ptcharslb = ptascii.size();
            }

            if (desiredpad%17 == 0) {
                ctlen-=16;

                if (cbc_mode) {
                    // Reset ctbuf back to original values
                    for (int j=0; j< 16; j++) {
                        ctbuf[ctlen-1-j] = prev_ctbuf_block[j];
                    }

                    for (int k=0; k<16; k++) {
                        prev_ctbuf_block[k] = ctbuf[ctlen-1-cbc_decr-k];
                    }
                }

                blocknum++;
                desiredpad=1;
                if (bytes_read-blocknum*16<=48) {
                    done=true;
                }
            }
        }
        std::cout.flush();
    }
    for (int i=ptascii.size()-1; i>=0; i--) {
        std::cerr << ptascii[i];
    }

    // clean up the pipes
    close(ofd[0]);
    close(ofd[1]);
    close(ifd[0]);
    close(ifd[1]);

    return 0;
}
