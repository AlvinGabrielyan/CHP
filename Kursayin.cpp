#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <fstream>
#include <algorithm>
#include <map>
using namespace std;

struct User {
    int user_id;
    string username;
    string password;
    string email;
    string role;
};

vector<User> users = {
    {1, "admin", "admin123", "admin@example.com", "administrator"},
    {2, "john", "password123", "john@example.com", "user"},
    {3, "alice", "secure456", "alice@example.com", "user"},
    {4, "bob", "bob789", "bob@example.com", "user"},
    {5, "sarah", "sarah123", "sarah@example.com", "manager"}
};

bool logAttempt(const string& username, bool success, const string& errorMsg = "");
void runSecureQuery();
void runVulnerableQuery();
void showUserData(const vector<User>& results);
void displayMenu();
bool validateInput(const string& input);

vector<User> executeVulnerableQuery(const string& query) {
    vector<User> results;
    cout << "Executing query: " << query << endl;

    string lowerQuery = query;
    transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

    if (lowerQuery.find("select") != string::npos &&
        lowerQuery.find("from users where") != string::npos) {

        size_t wherePos = lowerQuery.find("where");
        string conditions = lowerQuery.substr(wherePos + 5);

        if (conditions.find("'1'='1") != string::npos ||
            conditions.find("1=1") != string::npos) {
            return users;
        }

        for (const auto& user : users) {
            if (query.find(user.username) != string::npos &&
                query.find(user.password) != string::npos) {
                results.push_back(user);
                return results;
            }

            if (query.find("--") != string::npos || query.find("#") != string::npos) {
                size_t usernamePos = query.find(user.username);
                if (usernamePos != string::npos) {
                    results.push_back(user);
                    return results;
                }
            }
        }
    }
    else if (lowerQuery.find("select") != string::npos &&
        lowerQuery.find("like") != string::npos) {

        size_t likePos = lowerQuery.find("like");
        string searchCondition = lowerQuery.substr(likePos + 4);

        if (searchCondition.find("'1'='1") != string::npos ||
            searchCondition.find("1=1") != string::npos) {
            return users;
        }

        size_t firstQuote = searchCondition.find("'%");
        size_t lastQuote = searchCondition.find("%'");

        if (firstQuote != string::npos && lastQuote != string::npos) {
            string searchTerm = searchCondition.substr(firstQuote + 2, lastQuote - firstQuote - 2);

            for (const auto& user : users) {
                if (user.username.find(searchTerm) != string::npos ||
                    user.email.find(searchTerm) != string::npos) {
                    results.push_back(user);
                }
            }
        }
    }

    return results;
}

vector<User> executeSecureQuery(const string& queryTemplate, const map<int, string>& params) {
    vector<User> results;

    cout << "Executing parameterized query with template: " << queryTemplate << endl;
    cout << "Parameters: ";
    for (const auto& param : params) {
        cout << param.first << " = '" << param.second << "' ";
    }
    cout << endl;

    if (queryTemplate.find("SELECT user_id, username, role FROM users WHERE") != string::npos) {
        if (params.find(1) != params.end() && params.find(2) != params.end()) {
            string username = params.at(1);
            string password = params.at(2);

            for (const auto& user : users) {
                if (user.username == username && user.password == password) {
                    results.push_back(user);
                    return results;
                }
            }
        }
    }
    else if (queryTemplate.find("SELECT user_id, username, email, role FROM users") != string::npos) {
        if (params.find(1) != params.end()) {
            string searchTerm = params.at(1);
            searchTerm = searchTerm.substr(1, searchTerm.length() - 2);

            for (const auto& user : users) {
                if (user.username.find(searchTerm) != string::npos ||
                    user.email.find(searchTerm) != string::npos) {
                    results.push_back(user);
                }
            }
        }
    }

    return results;
}

int main() {
    string username, password;
    bool isLoggedIn = false;
    int loginAttempts = 0;
    const int MAX_ATTEMPTS = 3;

    cout << "=================================================\n";
    cout << "DATABASE AUTHENTICATION SYSTEM - DEMONSTRATION\n";
    cout << "=================================================\n";
    cout << "This program demonstrates SQL injection vulnerabilities\n";
    cout << "for educational purposes only.\n\n";

    cout << "Note: Using in-memory simulated database\n\n";

    while (loginAttempts < MAX_ATTEMPTS && !isLoggedIn) {
        cout << "LOGIN SCREEN (Attempt " << loginAttempts + 1 << " of " << MAX_ATTEMPTS << ")\n";
        cout << "Username: ";
        getline(cin, username);
        cout << "Password: ";
        getline(cin, password);

        string queryStr = "SELECT user_id, username, role FROM users WHERE username = '"
            + username + "' AND password = '" + password + "'";

        vector<User> results = executeVulnerableQuery(queryStr);

        if (!results.empty()) {
            isLoggedIn = true;
            const User& user = results[0];

            cout << "\nSUCCESS: Login successful!\n";
            cout << "User ID: " << user.user_id << endl;
            cout << "Username: " << user.username << endl;
            cout << "Role: " << user.role << endl << endl;

            logAttempt(username, true);

            if (results.size() > 1) {
                cout << "WARNING: Multiple users match the criteria - possible SQL injection!\n";
            }
        }
        else {
            cout << "ERROR: Invalid username or password.\n\n";
            logAttempt(username, false, "Invalid credentials");
        }

        loginAttempts++;

        if (!isLoggedIn && loginAttempts < MAX_ATTEMPTS) {
            cout << "Please try again.\n\n";
        }
    }

    if (isLoggedIn) {
        int choice = 0;

        while (choice != 5) {
            displayMenu();
            cout << "Enter your choice: ";
            cin >> choice;
            cin.ignore();

            string searchTerm;
            string queryStr;

            switch (choice) {
            case 1:
                cout << "Enter search term: ";
                getline(cin, searchTerm);

                cout << "VULNERABLE QUERY - Demonstrating SQL Injection Risk\n";
                cout << "-----------------------------------------------\n";

                queryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE '%"
                    + searchTerm + "%' OR email LIKE '%" + searchTerm + "%'";

                showUserData(executeVulnerableQuery(queryStr));
                break;

            case 2:
            {
                cout << "Enter search term: ";
                getline(cin, searchTerm);

                cout << "SAFE QUERY - Using Parameterized Statements\n";
                cout << "---------------------------------------\n";

                string paramQueryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ?";

                map<int, string> params;
                params[1] = "%" + searchTerm + "%";

                showUserData(executeSecureQuery(paramQueryStr, params));
            }
            break;

            case 3:
                runVulnerableQuery();
                break;

            case 4:
                runSecureQuery();
                break;

            case 5:
                cout << "Logging out...\n";
                break;

            default:
                cout << "Invalid choice. Please try again.\n";
            }

            if (choice != 5) {
                cout << "\nPress Enter to continue...";
                cin.get();
            }
        }
    }
    else {
        cout << "Maximum login attempts exceeded. Exiting.\n";
    }

    cout << "Program terminated.\n";
    return 0;
}

bool logAttempt(const string& username, bool success, const string& errorMsg) {
    time_t now = time(0);
    struct tm timeinfo;
    char timestamp[80];

    localtime_s(&timeinfo, &now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);

    ofstream logFile("auth_log.txt", ios::app);
    if (!logFile.is_open()) {
        cerr << "Failed to open log file.\n";
        return false;
    }

    logFile << timestamp << " | User: " << setw(15) << left << username
        << " | Status: " << (success ? "SUCCESS" : "FAILURE");

    if (!errorMsg.empty()) {
        logFile << " | Error: " << errorMsg;
    }

    logFile << endl;
    logFile.close();
    return true;
}

void showUserData(const vector<User>& results) {
    cout << setw(10) << left << "USER ID"
        << setw(20) << left << "USERNAME"
        << setw(30) << left << "EMAIL"
        << setw(15) << left << "ROLE" << endl;
    cout << string(75, '-') << endl;

    for (const auto& user : results) {
        cout << setw(10) << left << user.user_id
            << setw(20) << left << user.username
            << setw(30) << left << user.email
            << setw(15) << left << user.role << endl;
    }

    cout << string(75, '-') << endl;
    cout << results.size() << " record(s) found.\n";
}

void displayMenu() {
    cout << "\n=================================================\n";
    cout << "                   MAIN MENU                     \n";
    cout << "=================================================\n";
    cout << "1. Search users (vulnerable to SQL injection)\n";
    cout << "2. Search users (safe parameterized query)\n";
    cout << "3. Run SQL injection vulnerability demonstrations\n";
    cout << "4. Run secure query examples\n";
    cout << "5. Exit\n";
    cout << "-------------------------------------------------\n";
}

void runVulnerableQuery() {
    cout << "\n=================================================\n";
    cout << "       SQL INJECTION VULNERABILITY EXAMPLES       \n";
    cout << "=================================================\n";

    cout << "Would you like to run a simulated attack? (y/n): ";
    char choice;
    cin >> choice;
    cin.ignore();

    if (choice == 'y' || choice == 'Y') {
        string attackInput = "x' OR '1'='1";
        string queryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE '%" + attackInput + "%'";

        cout << "\nExecuting attack query: " << queryStr << endl << endl;

        vector<User> results = executeVulnerableQuery(queryStr);

        if (!results.empty()) {
            cout << "Attack successful! Displaying all users regardless of search term:\n\n";
            showUserData(results);
        }
        else {
            cout << "Attack simulation failed.\n";
        }
    }
}

void runSecureQuery() {
    cout << "\n=================================================\n";
    cout << "            SECURE QUERY EXAMPLES                \n";
    cout << "=================================================\n";

    cout << "Would you like to run a parameterized query demonstration? (y/n): ";
    char choice;
    cin >> choice;
    cin.ignore();

    if (choice == 'y' || choice == 'Y') {
        string searchTerm = "admin' OR '1'='1";
        cout << "\nSearching for malicious term: " << searchTerm << endl;

        string paramQueryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE ?";

        map<int, string> params;
        params[1] = "%" + searchTerm + "%";

        cout << "Executing parameterized query with search term treated as literal string\n\n";

        vector<User> results = executeSecureQuery(paramQueryStr, params);

        if (!results.empty()) {
            cout << "Query executed safely. Results:\n\n";
            showUserData(results);
            cout << "\nNotice how the injection attempt was treated as a literal string,\n";
            cout << "not as SQL code, preventing the attack.\n";
        }
        else {
            cout << "No results found for literal search term \"" << searchTerm << "\"\n";
            cout << "This demonstrates how parameterized queries protect against SQL injection.\n";
        }
    }
}

bool validateInput(const string& input) {
    vector<string> blacklist = {
        "'", "\"", ";", "--", "/*", "*/", "@@", "@",
        "char", "nchar", "varchar", "exec",
        "execute", "sp_", "xp_", "sysobjects", "syscolumns"
    };

    for (const auto& item : blacklist) {
        if (input.find(item) != string::npos) {
            return false;
        }
    }

    return true;
}
