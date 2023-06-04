#ifndef _BRIDGE_H_
#define _BRIDGE_H_

class Bridge {
    // Sets up the the bridge between two interfaces
    int SetUpConnection(const char* interface_a, const char* interface_b);
}

#endif // _BRIDGE_H_