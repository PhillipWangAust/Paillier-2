#ifndef AGENT_H
#define AGENT_H

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <gmp.h>
extern "C" 
{
  #include "paillier.h"
}
using namespace std;

class Agent {
private:
	int id;
	pair<double, double> state;
	pair<long, long> diff_state; 
        pair<double, double> m;
	pair<double, double> theta; // 0 ~ 100 random
	pair<double, double> beta; // (0, 0)
	pair<double,double> xbar;
	int alpha; // (0, m)
	int k;
	vector<Agent*> neighbors;

	paillier_pubkey_t* pubKey = NULL;
	paillier_prvkey_t* prvKey = NULL;

	void exchange(paillier_pubkey_t* pub, paillier_ciphertext_t* msg_in, paillier_ciphertext_t* msg_out, bool isFirst);
	long ciphertext_to_long(paillier_ciphertext_t* text);

public:
	Agent(int id);
	~Agent();

	pair<double, double> getState();
	void setState(pair<double, double> s);
	pair<double, double> getBeta() {
		return beta;
	}
	pair<double, double> getTheta() {
		return theta;
	}

	pair<long, long> getDiffState() {
		return diff_state;
	}
        pair<long, long> getC_res() {
		return m;
	}
	void pushToNeighbors(Agent* neighbor);

	void communicate();
	void communicate(bool isFirst);
	
	void updateState();
	void updateBeta();
	void updateAlpha();
};





























#endif
