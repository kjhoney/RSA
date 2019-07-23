#include <cstdio>
#include <cstdlib>
#include <time.h>
#include "xxhash.h"
#include <iostream>
using namespace std;

int p, q, r, N, phi, e, d, cipher, signature, value;
char buf[65], dbuf[65];
unsigned __int64 message, decrypted;
int Exp(int a, int b, int m);
int Gcd(int a, int b);
int Extended_Euclid(int m, int b);
int CRT(int c);
bool Miller_Rabin(int n);

void init() {
	srand(time(NULL));
	while(!Miller_Rabin(p))					// Miller_Rabin 함수를 이용해 p가 소수일 때 까지 반복
		p = rand() % 1024;					// Random한 p 생성
	while (!Miller_Rabin(q))				// Miller_Rabin 함수를 이용해 q가 소수일 때 까지 반복
		q = rand() % 1024;					// Random한 q 생성
	while (!Miller_Rabin(r))				// Miller_Rabin 함수를 이용해 r이 소수일 때 까지 반복
		r = rand() % 1024;					// Random한 r 생성
	N = p * q * r;
	phi = (p - 1) * (q - 1) * (r - 1);		// Totient N 값
	do { e = rand() % (phi - 1) + 1; } while (Gcd(e, phi) != 1);	// Totient N 값과 서로소인 e 랜덤생성
	d = Extended_Euclid(phi, e);									// d = e -1 mod phi
	printf("p = %d\nq = %d\nr = %d\nN = %d\nphi = %d\ne = %d\nd = %d\n\n", p, q, r, N, phi, e, d);
}

int Exp(int a, int b, int m) {				// Square and multiply 를 이용한 Exponentiation 함수 
	unsigned __int64 tmp = 1;
	unsigned __int64 square[30];
	square[0] = a;
	for (int i = 1; i < 30; i++)			// 밑이 a이고 지수가 2^0, 2^1, 2^2... 인 값들을 앞에 값을 제곱하면서 구해 저장 
		square[i] = (square[i - 1] * square[i - 1]) % m;

	for (int i = 0; i < 30; i++) {			// 지수의 비트가 1이면 해당 값을 배열에서 찾아 곱해줌
		if (b & (1 << i))
			tmp = (tmp * square[i]) % m;
	}
	return tmp;
}

int Gcd(int a, int b) {						// a와 b의 최대공약수를 찾는 함수
	if (!a) return b;
	else return Gcd(b%a, a);
}

int Extended_Euclid(int m, int b) {			// mod m 에대한 b의 역원을 찾는 함수
	int A[3] = { 1, 0, m };
	int B[3] = { 0, 1, b };
	while (1) {
		if (B[2] == 0)
			return 0;
		else if (B[2] == 1)
			return B[1] > 0 ? B[1] : (B[1] + m);
		int Q = A[2] / B[2];
		int T[3] = { A[0] - Q * B[0], A[1] - Q * B[1], A[2] - Q * B[2] };
		for (int i = 0; i < 3; i++) {
			A[i] = B[i];
			B[i] = T[i];
		}
	}
}

int CRT(int c) {							// CRT를 이용해 c^d mod N을 구하는 함수
	unsigned __int64 m1, m2, m3, d1, d2, d3, c1, c2, c3, res;
	d1 = d % (p - 1);
	d2 = d % (q - 1);
	d3 = d % (r - 1);
	m1 = Exp(c, d1, p);
	m2 = Exp(c, d2, q);
	m3 = Exp(c, d3, r);
	c1 = q * r * Extended_Euclid(p, q * r);
	c2 = p * r * Extended_Euclid(q, p * r);
	c3 = p * q * Extended_Euclid(r, p * q);
	res = (m1 * c1 + m2 * c2 + m3 * c3) % N;
	return res;
}

bool Miller_Rabin(int n) {					// Miller_Rabin을 이용해 n이 소수인지 판별하는 함수
	if (n < 2)
		return false;
	if (n != 2 && n % 2 == 0)
		return false;						// n이 짝수이거나, 2보다 작을 때는 소수가 아니다

	int tmp, a, k = 0, q = n - 1;

	while (q % 2 == 0) {					// n-1 = (2^k)*q 을 만족하는 q, k 값을 구함
		q /= 2;
		k++;
	}
	for (int i = 0; i < 20; i++) {			// 20회 Test
		a = rand() % (n - 3) + 2;			// 1 < a < n - 1 인 임의의 a 생성
		tmp = Exp(a, q, n);	
		if (tmp == 1 || tmp == n - 1)		// 유사소수
			continue;
		else {
			for (int j = 0; j < k - 1; j++) {
				tmp = (tmp * tmp) % n;
				if (tmp == n - 1)			// 유사소수
					break;
			}
			if (tmp != n - 1)				// 소수가 아닌경우
				return false;
		}
	}
	return true;							// 20회의 걸쳐 유사소수로 판별 되었으면 높은 확률로 소수이다
}


int main() {
	init();														// 기본 값 초기화 후 출력

	printf("Message Input : ");									//
	scanf("%I64u", &message);									// Message를 입력받고, 출력
	printf("Message : %I64u\n\n", message);						//

	printf("**Encryption\n");									//
	cipher = Exp(message, e, N);								// m^e mod N 으로 Encryption 후 출력
	printf("cipher : %d\n\n", cipher);							//

	printf("**Generate signature\n");							//
	sprintf(buf, "%I64u", message);								//
	unsigned __int64 hash = XXH64(buf, sizeof(buf) - 1, 0);		//
	hash = hash % N;											//
	printf("message's hash value : %I64u\n", hash);				// Cipher text를 hash함수를 통해 hash값으로 변환
	value = Exp(hash, d, N);									// hash^d mod N 으로 전자서명 생성 후 출력
	printf("generated signature : %d\n\n\n", value);			//

	printf("**Decryption\n");									//
	decrypted = CRT(cipher);									// Cipher text를 CRT를 이용해 Decryption 후 출력
	printf("decrypted cipher : %I64u\n\n", decrypted);			//

	printf("**Verify signature\n");
	printf("received signature value : %d\n", value);			// 넘겨받은 전자서명 출력
	sprintf(dbuf, "%I64u", decrypted);
	unsigned __int64 dhash = XXH64(dbuf, sizeof(dbuf) - 1, 0);
	dhash = dhash % N;
	printf("decrypted message's hash value : %I64u\n", dhash);	// 복호화한 Message를 hash 함수를 통해 hash값으로 변환 후 출력
	value = Exp(value, e, N);
	printf("verify value from signature : %d\n", value);		// 전자서명 S^e mod N 으로 원래 hash값 복원 후 출력
	if (value == dhash)											// value와 dhash 값을 비교해 verify
		printf("Signature valid!\n");
	else
		printf("Signature not valid!\n");
}