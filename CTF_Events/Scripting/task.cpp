#include <bits/stdc++.h>
using namespace std;

int main() {
#ifndef ONLINE_JUDGE
  // for getting input from input.txt
  freopen("a.txt", "r", stdin);
  // for writing output to output.txt
  freopen("output.txt", "w", stdout);
#endif

  char a;
  cin >> a;
  while (a != '}') {
    cout << a;
    cin >> a;
  }
}