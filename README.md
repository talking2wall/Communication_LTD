# Communication_LTD

## Summary
A secure website built with Flask & MySQL.
This website made as a final project for a course in cyber security, made in a group of 3 students.

This project include two versions of this website:
1. Vulnerable Version - created to demonstrate some MySQL & Stored-Xss vulnerabilities & bad practices.
2. Secured Version - a safe version of the same website (without the vulnerabilities).

GRADE : 100 of 100.
<br>


## Installation:
1. Creating the MySQL database.
2. Install flask and other dependencies
3. Create a self-signed certificate.
4. Run the App.py file.


## 1. Creating the MySQL database
To re-create the database follow these simple steps:
1. In your MySQL instance, create a new database called 'communication_ltd'.
2. Run the following MySQL query:
```
CREATE TABLE `users` (
  `userid` int NOT NULL AUTO_INCREMENT,
  `FirstName` varchar(30) DEFAULT NULL,
  `LastName` varchar(30) DEFAULT NULL,
  `Email` varchar(50) NOT NULL,
  `Username` varchar(50) NOT NULL,
  `Password` varchar(100) NOT NULL,
  `WrongLoginAttemptCount` int DEFAULT '0',
  `Token` varchar(255) DEFAULT NULL,
  `TokenDate` datetime DEFAULT NULL,
  `Admin` tinyint DEFAULT '0',
  PRIMARY KEY (`userid`,`Email`,`Username`,`Password`)
) ENGINE=InnoDB AUTO_INCREMENT=79 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `passwords_history` (
  `userid` int NOT NULL,
  `Password` varchar(100) NOT NULL,
  `DateChanged` datetime NOT NULL,
  PRIMARY KEY (`userid`,`Password`,`DateChanged`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

After you ran this long query you should be able to see 2 new tables appear in your database.

## Actual Images
![image](https://user-images.githubusercontent.com/18194032/209861919-232b8565-b680-45cf-9212-c3c3cf42e808.png)
![image](https://user-images.githubusercontent.com/18194032/209861971-256d4b63-0a4d-49a7-87e8-3c64c31c3a21.png)
![image](https://user-images.githubusercontent.com/18194032/209862014-c54bc87a-8be0-4596-a637-db99e140b8dd.png)
![image](https://user-images.githubusercontent.com/18194032/209862122-3e0eaf77-30cb-44d1-9b76-5ba2c2681389.png)
