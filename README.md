## SECURE FILE STORAGE SYSTEM


### Intro
_____________________

This system is built with intent to store files and ensure confidentality , integrity and availability.

I developed this as a school project.

### What happening?
______________________

#### user functionalities
A user can register and account on the system by providing their email , username and password.

The system allows a user to upload files which are then encrypted and stored on the system. Users can choose the permission of the uploaded file , whether private or public.

Each user has ther own folder that their files are stored in , there is also public folder that can be accessed by all users.

A user can also download their files which are then decrypted from the storage.

#### admin functionalities

The system also has an admin user that manages the files and users. The admin also need to approve a new user so that they can use the system. 

The admin also has an option to unarchive files. Files marked as archived are hidden from view but  still  stored on the system.

The admin cancreate backups of files and database of the system and also managae these backups.


The system also has a report generation feature that can create reports based on data from the database tables.


You can also get the user manual [here](/static/user_manual.pdf)

### Techical aspects 
_______________________________

The system is built with flask webapplication framework. The choice for this was familiarily with the python language.


The database is sqlite. With table for :
* Users
* Files
* Backups
* role
* permissions

This is suitable for the system in its small size.

When the app is instanciated it creates and 
* admin : password
* test : test

This happens in the main.py when populating the database for testing purposes.

The system user AES ecrytion to encrypt files that are stored. And a Sha256 hash of each file is generated.

The backups are created by making copies of files and database. The backups are names the iso time format of the time the backup is created.

The report generation feature is usng python reportlab module.

The system supports https protocol by using an reverse proxy. This feature can be accessed when you build the docker container.

#### todo

- [x] fix security vulnerabilities
- [x] create a  separate container for the nginx
- [x] mount volumes to the container to store files  

### Outro


I am proud that i was able to learn new things when creating this system. I should prolly try and ensure i fix obvious security issues in the code. It isnt the most secure from a cybersecurity guys perspective :).
Feel free to play around with it.


