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
	while(!Miller_Rabin(p))					// Miller_Rabin �Լ��� �̿��� p�� �Ҽ��� �� ���� �ݺ�
		p = rand() % 1024;					// Random�� p ����
	while (!Miller_Rabin(q))				// Miller_Rabin �Լ��� �̿��� q�� �Ҽ��� �� ���� �ݺ�
		q = rand() % 1024;					// Random�� q ����
	while (!Miller_Rabin(r))				// Miller_Rabin �Լ��� �̿��� r�� �Ҽ��� �� ���� �ݺ�
		r = rand() % 1024;					// Random�� r ����
	N = p * q * r;
	phi = (p - 1) * (q - 1) * (r - 1);		// Totient N ��
	do { e = rand() % (phi - 1) + 1; } while (Gcd(e, phi) != 1);	// Totient N ���� ���μ��� e ��������
	d = Extended_Euclid(phi, e);									// d = e -1 mod phi
	printf("p = %d\nq = %d\nr = %d\nN = %d\nphi = %d\ne = %d\nd = %d\n\n", p, q, r, N, phi, e, d);
}

int Exp(int a, int b, int m) {				// Square and multiply �� �̿��� Exponentiation �Լ� 
	unsigned __int64 tmp = 1;
	unsigned __int64 square[30];
	square[0] = a;
	for (int i = 1; i < 30; i++)			// ���� a�̰� ������ 2^0, 2^1, 2^2... �� ������ �տ� ���� �����ϸ鼭 ���� ���� 
		square[i] = (square[i - 1] * square[i - 1]) % m;

	for (int i = 0; i < 30; i++) {			// ������ ��Ʈ�� 1�̸� �ش� ���� �迭���� ã�� ������
		if (b & (1 << i))
			tmp = (tmp * square[i]) % m;
	}
	return tmp;
}

int Gcd(int a, int b) {						// a�� b�� �ִ������� ã�� �Լ�
	if (!a) return b;
	else return Gcd(b%a, a);
}

int Extended_Euclid(int m, int b) {			// mod m ������ b�� ������ ã�� �Լ�
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

int CRT(int c) {							// CRT�� �̿��� c^d mod N�� ���ϴ� �Լ�
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

bool Miller_Rabin(int n) {					// Miller_Rabin�� �̿��� n�� �Ҽ����� �Ǻ��ϴ� �Լ�
	if (n < 2)
		return false;
	if (n != 2 && n % 2 == 0)
		return false;						// n�� ¦���̰ų�, 2���� ���� ���� �Ҽ��� �ƴϴ�

	int tmp, a, k = 0, q = n - 1;

	while (q % 2 == 0) {					// n-1 = (2^k)*q �� �����ϴ� q, k ���� ����
		q /= 2;
		k++;
	}
	for (int i = 0; i < 20; i++) {			// 20ȸ Test
		a = rand() % (n - 3) + 2;			// 1 < a < n - 1 �� ������ a ����
		tmp = Exp(a, q, n);	
		if (tmp == 1 || tmp == n - 1)		// ����Ҽ�
			continue;
		else {
			for (int j = 0; j < k - 1; j++) {
				tmp = (tmp * tmp) % n;
				if (tmp == n - 1)			// ����Ҽ�
					break;
			}
			if (tmp != n - 1)				// �Ҽ��� �ƴѰ��
				return false;
		}
	}
	return true;							// 20ȸ�� ���� ����Ҽ��� �Ǻ� �Ǿ����� ���� Ȯ���� �Ҽ��̴�
}


int main() {
	init();														// �⺻ �� �ʱ�ȭ �� ���

	printf("Message Input : ");									//
	scanf("%I64u", &message);									// Message�� �Է¹ް�, ���
	printf("Message : %I64u\n\n", message);						//

	printf("**Encryption\n");									//
	cipher = Exp(message, e, N);								// m^e mod N ���� Encryption �� ���
	printf("cipher : %d\n\n", cipher);							//

	printf("**Generate signature\n");							//
	sprintf(buf, "%I64u", message);								//
	unsigned __int64 hash = XXH64(buf, sizeof(buf) - 1, 0);		//
	hash = hash % N;											//
	printf("message's hash value : %I64u\n", hash);				// Cipher text�� hash�Լ��� ���� hash������ ��ȯ
	value = Exp(hash, d, N);									// hash^d mod N ���� ���ڼ��� ���� �� ���
	printf("generated signature : %d\n\n\n", value);			//

	printf("**Decryption\n");									//
	decrypted = CRT(cipher);									// Cipher text�� CRT�� �̿��� Decryption �� ���
	printf("decrypted cipher : %I64u\n\n", decrypted);			//

	printf("**Verify signature\n");
	printf("received signature value : %d\n", value);			// �Ѱܹ��� ���ڼ��� ���
	sprintf(dbuf, "%I64u", decrypted);
	unsigned __int64 dhash = XXH64(dbuf, sizeof(dbuf) - 1, 0);
	dhash = dhash % N;
	printf("decrypted message's hash value : %I64u\n", dhash);	// ��ȣȭ�� Message�� hash �Լ��� ���� hash������ ��ȯ �� ���
	value = Exp(value, e, N);
	printf("verify value from signature : %d\n", value);		// ���ڼ��� S^e mod N ���� ���� hash�� ���� �� ���
	if (value == dhash)											// value�� dhash ���� ���� verify
		printf("Signature valid!\n");
	else
		printf("Signature not valid!\n");
}