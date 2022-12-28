# Communication_LTD
A secure website built with Flask & MySQL.

***Important Note:** The project is activly being developed at the moment.

<br>


## Creating the MySQL database
To create the same database we used, please follow this simple procedure:
1. In your MySQL instance, create a new database called 'communication_ltd'.
2. Run the following MySQL query:
```
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `FirstName` varchar(30) DEFAULT NULL,
  `LastName` varchar(30) DEFAULT NULL,
  `Email` varchar(35) NOT NULL,
  `Username` varchar(35) NOT NULL,
  `Password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`,`Email`,`Username`,`Password`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

## Actual Images
![image](https://user-images.githubusercontent.com/18194032/209861919-232b8565-b680-45cf-9212-c3c3cf42e808.png)
![image](https://user-images.githubusercontent.com/18194032/209861971-256d4b63-0a4d-49a7-87e8-3c64c31c3a21.png)
![image](https://user-images.githubusercontent.com/18194032/209862014-c54bc87a-8be0-4596-a637-db99e140b8dd.png)
![image](https://user-images.githubusercontent.com/18194032/209862122-3e0eaf77-30cb-44d1-9b76-5ba2c2681389.png)
