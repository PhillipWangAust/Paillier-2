#include "Agent.h"
#include <math.h>
#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>
#include <ctime>
using namespace std;

#define KEY_LENGTH 256
#define STATE_FACTOR 100000
#define TOTAL_AGENT 4
#define ALPHA_FACTOR 1000




FILE* cipherTextFile;


Agent::Agent(int id): id(id), theta(make_pair(rand() % 100+1, rand() % 100+1)), state(make_pair(rand() % 100+1, rand() % 100+1)),beta(make_pair(0, 0)), xbar(make_pair(50, 45)), diff_state(make_pair(0, 0)), alpha(rand() % 500+500), k(1) {
	paillier_keygen(KEY_LENGTH, &pubKey, &prvKey, paillier_get_rand_devurandom);
	//updateAlpha();
	//cout << "The " << id << "th agent, alpha = " << alpha << "; Theta: (" << theta.first << ", " << theta.second << ")" <<endl;	
}

Agent::~Agent() {
	paillier_freepubkey(pubKey);
	paillier_freeprvkey(prvKey);
}


pair<double, double> Agent::getState() {
	return state;
}

/*void Agent::setState(pair<double, double> s) {
	state = s;
}*/

void Agent::pushToNeighbors(Agent* neighbor) {
	neighbors.push_back(neighbor);
}

void Agent::communicate() {
	diff_state = make_pair(0, 0); // reset to (0, 0) 
	// clock_t begin = clock();
	communicate(true);

	// clock_t end = clock();
	// cout << double(end - begin) / CLOCKS_PER_SEC <<endl;

	communicate(false);
}

void Agent::communicate(bool isFirst) {
	// Convert and encrypt the current state
	// May want to log enc_state
	long long_state = -(long) lround((isFirst? state.first : state.second) * STATE_FACTOR);

	
	// Plaintext initialization
	paillier_plaintext_t* m_s = paillier_plaintext_from_ui(long_state);
        // encrypt the state
	paillier_ciphertext_t* c_s = NULL;
	c_s = paillier_enc(NULL, pubKey, m_s,
		     paillier_get_rand_devurandom);
	// Initialize the ciphertext that will hold the sum with an encryption of zero
	paillier_ciphertext_t* c_res = paillier_create_enc_zero();
	/*
	For each peer in the list,
	> Communicate
	> add to diff_state
	*/


	long result =0;

	for(auto it = neighbors.begin(); it != neighbors.end(); ++it)
	{

		(*it)->exchange(pubKey, c_s, c_res, isFirst);

		gmp_fprintf(cipherTextFile,"%Zu\t", c_res);

	
		result = ciphertext_to_long(c_res);
		isFirst? diff_state.first += alpha * result : diff_state.second += alpha * result;
	}
	fprintf(cipherTextFile, "\n");
	fprintf(cipherTextFile, "\n");


	paillier_freeplaintext(m_s);
	paillier_freeciphertext(c_s);
	paillier_freeciphertext(c_res);
}


void Agent::exchange(paillier_pubkey_t* pub, paillier_ciphertext_t* msg_in, paillier_ciphertext_t* msg_out, bool isFirst) {
	// create the negative of the current state
	long long_state = (long) lround((isFirst? state.first : state.second) * STATE_FACTOR);

	// encrypt the state
	paillier_plaintext_t* m_s = paillier_plaintext_from_ui(long_state); // long to text
	paillier_plaintext_t* m_a = paillier_plaintext_from_ui(alpha);

	paillier_ciphertext_t* c_s = NULL;
	c_s = paillier_enc(NULL, pub, m_s,
		     paillier_get_rand_devurandom); // 加密

	paillier_ciphertext_t* c_d = paillier_create_enc_zero();

	// c_d = ENC( x_j + (-x_i) ) 输出值
	paillier_mul(pub, c_d, msg_in, c_s);

	if (msg_out == NULL)
	msg_out = paillier_create_enc_zero();

	// msg_out = ENC( alpha * (x_j + (-x_i) )
	paillier_exp(pub, msg_out, c_d, m_a);


	paillier_freeplaintext(m_s);
	paillier_freeplaintext(m_a);
	paillier_freeciphertext(c_s);
	paillier_freeciphertext(c_d);
}

long Agent::ciphertext_to_long(paillier_ciphertext_t* c) {
	paillier_plaintext_t* m = paillier_dec(NULL, pubKey, prvKey, c); //解密 to text
	//gmp_printf("Decrypted sum: %Zu\n", c);
	cout << endl;


	size_t nBytes = 0;
	unsigned char* bytes = (unsigned char*) mpz_export(0, &nBytes, 1, 1, 0, 0, m->m);


	long int e = 0;
	//  assert( nBytes > sizeof(a));
	//  for(int i=nBytes-1; i >= nBytes-sizeof(a); --i)
	for(int i= nBytes-sizeof(long); i < nBytes; i++)
	{
	  e = (e << 8) | bytes[i];
	}
       // cout << "e:" << e << endl;
	paillier_freeplaintext(m);
	free(bytes);
	return e;
        
}


void Agent::updateState() {
	//communicate();
	double R;
	R=(theta.first-xbar.first)*(theta.first-xbar.first)+(theta.second-xbar.second)*(theta.second-xbar.second);
	if((beta.first-theta.first)*(beta.first-theta.first)+(beta.second-theta.second)*(beta.second-theta.second)<=R) {
      state.first=beta.first;
      state.second=beta.second;
   } else {
     state.first=theta.first+sqrt(R)*(beta.first-theta.first)/(sqrt((beta.first-theta.first)*(beta.first-theta.first)+(beta.second-theta.second)*(beta.second-theta.second)));
     state.second=theta.second+sqrt(R)*(beta.second-theta.second)/(sqrt((beta.first-theta.first)*(beta.first-theta.first)+(beta.second-theta.second)*(beta.second-theta.second)));
   }
     //state.first=theta.first+sqrt(R)*(beta.first-theta.first)/(sqrt((beta.first-theta.first)*(beta.first-theta.first)+(beta.second-theta.second)*(beta.second-theta.second)));
     //state.second=theta.second+sqrt(R)*(beta.second-theta.second)/(sqrt((beta.first-theta.first)*(beta.first-theta.first)+(beta.second-theta.second)*(beta.second-theta.second)));
   
 
    cout << "R:" <<R << " " ;

	cout << "State: (" << state.first << ", " << state.second << ")  ";
}

void Agent::updateBeta() {
	//communicate();
	beta.first =state.first+double(diff_state.first) / STATE_FACTOR / TOTAL_AGENT / ALPHA_FACTOR / ALPHA_FACTOR;
	beta.second = state.second+double(diff_state.second) / STATE_FACTOR / TOTAL_AGENT / ALPHA_FACTOR / ALPHA_FACTOR;
	double aa=double(diff_state.first) / STATE_FACTOR / TOTAL_AGENT / ALPHA_FACTOR / ALPHA_FACTOR;
	double bb=double(diff_state.second) / STATE_FACTOR / TOTAL_AGENT / ALPHA_FACTOR / ALPHA_FACTOR;
		cout << "Beta: (" << beta.first << ", " << beta.second << ")  " << endl;
		cout << "Diffstate: (" << aa << ", " << bb<< ") "<<endl; 
}

void Agent::updateAlpha() {
	alpha = rand() % (ALPHA_FACTOR / 2) + ALPHA_FACTOR / 2;
	//alpha=500;
      //  alpha = alpha+rand() % 5;
	cout << " alpha: " << alpha <<endl;
}


/*
int main() {
	srand(time(NULL));
	int numStep = 100;
	vector<Agent*> agents;
	double avg_x = 0, avg_y = 0;
	for (int i = 0; i < TOTAL_AGENT; i++) {
		agents.push_back(new Agent(i));
		auto theta_pair = agents[i]->getTheta();
		avg_x += theta_pair.first;
		avg_y += theta_pair.second;
	}
	//cout<< avg_x <<" "<< avg_y << " " << TOTAL_AGENT <<" avg: (" << avg_x / TOTAL_AGENT << ", " << avg_y / TOTAL_AGENT << ")" <<endl;
	agents[0]->pushToNeighbors(agents[1]);
	agents[0]->pushToNeighbors(agents[2]);
	agents[0]->pushToNeighbors(agents[4]);

	agents[1]->pushToNeighbors(agents[0]);
	agents[1]->pushToNeighbors(agents[2]);

	agents[2]->pushToNeighbors(agents[0]);
	agents[2]->pushToNeighbors(agents[1]);


	agents[3]->pushToNeighbors(agents[4]);

	agents[4]->pushToNeighbors(agents[0]);
	agents[4]->pushToNeighbors(agents[3]);

	for (int i = 0; i < numStep; i++) {
		//cout << "Step " << i << ": ";
		for (int j = 0; j < agents.size(); j++) agents[j]->updateState();
		for (int j = 0; j < agents.size(); j++) agents[j]->updateBeta();
	}
	
	for (int i = 0; i < TOTAL_AGENT; i++) delete agents[i];


}
*/




int main() {
	cipherTextFile = fopen("cipherText.txt", "w");

        ofstream outputState, outputDiffState, outputTime, outputC_res;
	outputState.open("outputState.txt");
	outputDiffState.open("diffStateAgent1.txt");
	outputTime.open("outputTime.txt");
        outputC_res.open("outputC_res.txt");
	srand(time(NULL));
	int numStep = 50;
	vector<Agent*> agents;
	double avg_x = 0, avg_y = 0;
	for (int i = 0; i < TOTAL_AGENT; i++) {
		agents.push_back(new Agent(i));
		auto theta_pair = agents[i]->getTheta();
		avg_x += theta_pair.first;
		avg_y += theta_pair.second;
		cout << "theta: ("<<theta_pair.first<<", "<<theta_pair.second<<") ";
	}
	
	agents[0]->pushToNeighbors(agents[1]);
	agents[0]->pushToNeighbors(agents[2]);
	agents[0]->pushToNeighbors(agents[3]);
	agents[1]->pushToNeighbors(agents[0]);
	agents[1]->pushToNeighbors(agents[2]);
	agents[1]->pushToNeighbors(agents[3]);
	agents[2]->pushToNeighbors(agents[0]);
	agents[2]->pushToNeighbors(agents[1]);
	agents[2]->pushToNeighbors(agents[3]);  
	agents[3]->pushToNeighbors(agents[0]);
	agents[3]->pushToNeighbors(agents[1]);
	agents[3]->pushToNeighbors(agents[2]);
	/*agents[4]->pushToNeighbors(agents[1]);
	agents[4]->pushToNeighbors(agents[2]);
	agents[4]->pushToNeighbors(agents[3]);
	agents[4]->pushToNeighbors(agents[5]);
	agents[5]->pushToNeighbors(agents[0]);
	agents[5]->pushToNeighbors(agents[4]);*/
	
	for (int i = 0; i < numStep; i++) {
		////cout << "Step " << i << ": ";
		//outputState << "step " << i << ": ";
		for (int j = 0; j < agents.size(); j++) {
			agents[j]->updateAlpha();
		}

		for (int j = 0; j < agents.size(); j++) {
			clock_t begin = clock();
			agents[j]->communicate();
			clock_t end = clock();
			outputTime << double(end - begin) / CLOCKS_PER_SEC * 1000 << endl;
		}

		pair<long, long> diffStateOfAgent1 = agents[0] -> getDiffState();
		outputDiffState << diffStateOfAgent1.first / STATE_FACTOR << " " << diffStateOfAgent1.second / STATE_FACTOR << endl;

                pair<double, double> C_resOfAgent1 = agents[0] -> getC_res();
		outputC_res << C_resOfAgent1.first  << " " << C_resOfAgent1.second << endl;

		for (int j = 0; j < agents.size(); j++) {
			agents[j]->updateBeta();
			agents[j]->updateState();
			pair<double, double> stateRes = agents[j] -> getState();
			outputState << stateRes.first << " " << stateRes.second << "	";
		}
		outputState << endl;


		/*
		for (int j = 0; j < agents.size(); j++) {
			agents[j]->updateState();
			pair<double, double> res = agents[j] -> getState();
			cout << res.first << " " << res.second << " ";
		}
		cout << endl;


		for (int j = 0; j < agents.size(); j++) {ciphertext_to_long
			agents[j]->updateBeta();
			// pair<double, double> res = agents[j] -> getBeta();
			// outputBeta << res.first << " " << res.second << " ";
		}
		//outputBeta << endl;

		////cout << endl;

		*/

	}
	cout<< avg_x <<" "<< avg_y << " " << TOTAL_AGENT <<" avg: (" << avg_x / TOTAL_AGENT << ", " << avg_y / TOTAL_AGENT << ")" <<endl;


	for (int i = 0; i < TOTAL_AGENT; i++) 
		delete agents[i];
	// outputState.close();
	// outputBeta.close();
}	



