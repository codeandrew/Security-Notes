


## LABS


### DATABASES STATEMENTS
```mysql
Ubuntu@tryhackme:~$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.39-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> CREATE DATABASE thm_bookmarket_db;
Query OK, 1 row affected (0.01 sec)

mysql> SHOW DATABASES;
+-----------------------------------------------+
| Database                                      |
+-----------------------------------------------+
| THM{575a947132312f97b30ee5aeebba629b723d30f9} |
| information_schema                            |
| mysql                                         |
| performance_schema                            |
| sys                                           |
| task_4_db                                     |
| thm_bookmarket_db                             |
| thm_books                                     |
| thm_books2                                    |
| tools_db                                      |
+-----------------------------------------------+
10 rows in set (0.01 sec)

mysql> USE thm_bookmarket_db;
Database changed
mysql> CREATE TABLE book_inventory (
    ->     book_id INT AUTO_INCREMENT PRIMARY KEY,
    ->     book_name VARCHAR(255) NOT NULL,
    ->     publication_date DATE
    -> );
Query OK, 0 rows affected (0.04 sec)

mysql> SHOW TABLES;
+-----------------------------+
| Tables_in_thm_bookmarket_db |
+-----------------------------+
| book_inventory              |
+-----------------------------+
1 row in set (0.00 sec)

mysql> DESCRIBE book_inventory;
+------------------+--------------+------+-----+---------+----------------+
| Field            | Type         | Null | Key | Default | Extra          |
+------------------+--------------+------+-----+---------+----------------+
| book_id          | int          | NO   | PRI | NULL    | auto_increment |
| book_name        | varchar(255) | NO   |     | NULL    |                |
| publication_date | date         | YES  |     | NULL    |                |
+------------------+--------------+------+-----+---------+----------------+
3 rows in set (0.00 sec)

mysql> ALTER TABLE book_inventory;
Query OK, 0 rows affected (0.02 sec)

mysql> ALTER TABLE book_inventory ADD page_count INT;
Query OK, 0 rows affected (0.04 sec)
Records: 0  Duplicates: 0  Warnings: 0

mysql> 


mysql> SHOW DATABASES;
+-----------------------------------------------+
| Database                                      |
+-----------------------------------------------+
| THM{575a947132312f97b30ee5aeebba629b723d30f9} |
| information_schema                            |
| mysql                                         |
| performance_schema                            |
| sys                                           |
| task_4_db                                     |
| thm_bookmarket_db                             |
| thm_books                                     |
| thm_books2                                    |
| tools_db                                      |
+-----------------------------------------------+
10 rows in set (0.00 sec)

mysql> USE task_4_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> SHOW TABLES;
+-----------------------------------------------+
| Tables_in_task_4_db                           |
+-----------------------------------------------+
| THM{692aa7eaec2a2a827f4d1a8bed1f90e5e49d2410} |
+-----------------------------------------------+
1 row in set (0.00 sec)

```
