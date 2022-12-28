# Communication_LTD
A secure website built with Flask & MySQL.

# Creation of the MySQL database
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
