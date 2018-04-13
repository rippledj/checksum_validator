# Application File Locker

**Author:** Joseph Lee
**Email:** joseph.lee.esl@gmail.com


## Description

Application Checksum Validator is a application locker using MD5 checksums to
validate all contents of your application or other directories and files.
Application maps and exclusion/inclusion files are then tracked using logs.
The map is encrypted using a password that must be included in the command line
execution as a flag.

## Instructions

1. Open the file checksum_validator.py in an text editor.
2. Configuration settings are at the top of the main function.  These include:
  * *email_server_array* SMPTP mail server settings to send the report mail.
  * *email_report* and *report_to_file* to set how reports are handled
  * *email_report_to_address_array* list of email addresses to send report to
  * *scan_base_directory_path* if you want the base dirpath set as variable as opposed to command line. Otherwise leave blank.
3. edit the *exclusion.cnf* file with files and/or directories to ignore in map and validate process. Note: once the map is created, the exclusion settings cannot be changed unless the map is reset.
4. run the python script with password and application dirpath (optional otherwise *scan_base_directory_path* in file will be used) to create a map:
  $ python checksum_validator.py -map -p <password> -f /path/to/application/
5. run the python script with password and application dirpath (optional otherwise *scan_base_directory_path* in file will be used) to validate map:
  $ python checksum_validator.py -validate -p <password> -f /path/to/application/
6. Schedule this application to run periodically.

## Additional Security Recommendations

1. Hide the validator directory in your file structure
2. Rename the directory and script before you schedule it so that it cannot be found by name

## TODO List

* create a '-reset' argument to reset the application map after making changes
* create a mode to include a list of directories and files to include in the map/validation
* create an option to only send email report if problem found
