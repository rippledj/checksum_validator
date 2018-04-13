#!/usr/bin/env python
# Application Checksum Validator

# Description--
# Application Checksum Validator is a application locker using MD5 checksums to
# validate all contents of your application or other directories and files.
# Application maps and exclusion/inclusion files are then tracked using logs.
# Author: Joseph Lee
# Email: joseph.lee.esl@gmail.com

#TODO: create a mode to include a list of directories and files to include in the map/validation
#TODO: create a better way to reset the exclusion file, i.e. use existing file if exists.
#TODO: write inclusion file as encrypted, decrypt for use with validate,
#TODO: when -reset specified with exclusion or all, then rewrite the exclusion file as unencrypted
# don't run the map immediately, and print message to user that they should make change and run map again.

## Import Modules ##
import os
import sys
import logging
import time
import datetime
import string
import hashlib
from Crypto.Cipher import AES
import smtplib

## Function to read locker files and filepaths into single array
def create_file_map(filepath, exclusion_set_array):

	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")
	try:
		# Build the filepath map of the application filepath
		# Array contents = [[directories],[filenames],[excluded directories], [excluded filenames]]
		filepath_array = [[],[],[],[]]
		for (dirpath, dirnames, filenames) in os.walk(filepath):
				# Build array of files
				for filename in filenames:
					#print filename
					# Set a flag to check exclusion test pass
					exclusion_test_pass = False
					# Create correct fullpath_string
					if dirpath == filepath: fullpath_string = dirpath + filename
					else: fullpath_string = dirpath + "/" + filename
					# Remove scan_base_directory_path to check exclusion set
					exclusion_check_string = "/" + fullpath_string.replace(scan_base_directory_path, "")
					# create variable to check nested directory path for ignore compliance
					nested_directory_path = exclusion_check_string.split("/")
					nested_directory_path.pop(len(nested_directory_path) - 1)
					nested_directory_path.pop(0)
					nested_directory_path = "/" + '/'.join(nested_directory_path) + "/"
					# Check that dirpath is not in excluded set
					if exclusion_check_string not in exclusion_set_array and nested_directory_path not in exclusion_set_array:
						# Set exclusion set to pass, based on directory
						exclusion_test_pass = True
						# Check that filename is not in exclusion set
						for item in exclusion_set_array:
							# directory items have `/` at start and end, so look for items without this
							# Global file exclusion
							if len(item) == len(item.strip("/")):
								# Check that filename is not globally excluded
								if filename == item:
									exclusion_test_pass = False
						if exclusion_test_pass:
							# Append to array of files
							filepath_array[1].append(fullpath_string)
							#print exclusion_check_string
					# Else add the filename to excluded array
					else:
						# Append to list of files in exclusion set.
						filepath_array[3].append(fullpath_string)
				# Build array of directories
				for directory in dirnames:
					# Set a flag to check exclusion test pass
					exclusion_test_pass = False
					# Create correct fullpath_string
					if dirpath == filepath: fullpath_string = dirpath + directory + "/"
					else: fullpath_string = dirpath + "/" + directory + "/"
					# Remove scan_base_directory_path to check exclusion set
					exclusion_check_string = "/" + fullpath_string.replace(scan_base_directory_path, "")
					# Check that dirpath/directory/ is not in excluded set
					if exclusion_check_string not in exclusion_set_array:
						exclusion_test_pass = True
						# Check that exclusion set is further not violated in terms of
						# multi-nested directories in a base ignore directory
						for item in exclusion_set_array:
							if item in exclusion_check_string:
								exclusion_test_pass = False
						# If passed exlcusion set requirements
						if exclusion_test_pass == True:
							# Append to list of directories
							filepath_array[0].append(fullpath_string)
						else:
							# Append to list of directories in exclusion set.
							filepath_array[2].append(fullpath_string)
						#print exclusion_check_string
					# Else add the dirpath and directory to excluded array
					else:
						# Append to list of directories in exclusion set.
						filepath_array[2].append(fullpath_string)

		#print filepath_array
		# Return the array
		return filepath_array

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Error creating filepath map: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error creating filepath map: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Check the encrypted map file to make sure password is ok.
def check_password_integrity(working_directory, scan_base_directory_path, key):

	try:
		# Open encrypted file with key
		with open(working_directory + "/log/" + scan_base_directory_path.strip("/").replace("/", "_") + "_data") as data_file:
			original_file_content = data_file.read()

		# Decrypt the file from encrypted format
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		decryptor = AES.new(key, mode, IV=IV)
		original_file_content = decryptor.decrypt(original_file_content).split("\n")

		# Check that the first line is the password correct confirmation
		# If the password confirmation is not correct, then return false
		if original_file_content[0] != "++++":
			print "Incorrect Password!"
			return False
		else:
			return True

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		#print 'Error resetting checksum map: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error resetting checksum map: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

## Create a checksum map in a file
def create_checksum_map(filepath_array, data_file, scan_base_directory_path, arg, key=None):

	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")

	try:
		# If the argument passed is to process validation checksum map
		if arg == "validate":

			# Create array to store data
			validate_filepath_array = [[],[],[]]

			# Edit the array inline by adding md5 checksum and comma character
			# so the array can be written directly to file in CSV

			# Iterate through the filepath array of directories
			for item in filepath_array[0]:
				#print item
				validate_filepath_array[0].append(item)
			# Iterate through the filepath array of files
			for item in filepath_array[1]:
				#print item
				# Get the md5 checksum of the file contents
				md5_checksum = hashlib.md5(open(item, 'rb').read()).hexdigest()
				# Add the checksum to the array
				validate_filepath_array[1].append(item)
				validate_filepath_array[2].append(md5_checksum)

			# return validate_filepath_array
			return validate_filepath_array

		# If the argument passed is to process mapping checksum map
		if arg == "map":
			# Edit the array inline by adding md5 checksum and comma character
			# so the array can be written directly to file in CSV
			for i, item in enumerate(filepath_array[1]):
				# Get the md5 checksum of the file contents
				md5_checksum = hashlib.md5(open(item, 'rb').read()).hexdigest()
				# Prepare the array with CSV for writing
				filepath_array[1][i] = item + "," + md5_checksum
			# Call function to write the checksum map to file
			write_checksum_to_file(filepath_array, data_file, key)

			# Return True for success
			return True

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Error creating checksum map: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error creating checksum map: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

## Write to file
def write_checksum_to_file(filepath_array, data_file, key):

	try:
		# Write data to file
		data_file = open(data_file, "w+")
		# Create a string to write to file
		data_string = "++++\n"
		for item in filepath_array[0]:
			data_string += item + "\n"
		# Write file and checksum data to file
		for item in filepath_array[1]:
			data_string += item + "\n"

		# Encode data string to utf-8 to make sure it's common encoding
		data_string = data_string.encode('utf-8')

		# Encrypt the data string to be written to file with padding
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		encryptor = AES.new(key, mode, IV=IV)
		data_in_ciphertext = encryptor.encrypt(data_string + ((16 - len(data_string)%16) * "@"))

		# Write the encrypted data to file
		data_file.write(data_in_ciphertext)
		# Close the file
		data_file.close();

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Error writing checksum map to file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error writing checksum map to file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Iteration of bytes of each file
def hash_bytestr_iter(bytesiter, hasher, ashexstr=False):
    for block in bytesiter:
        hasher.update(block)
    return (hasher.hexdigest() if ashexstr else hasher.digest())

# Iteration of blocks to file
def file_as_blockiter(afile, blocksize=65536):
    with afile:
        block = afile.read(blocksize)
        while len(block) > 0:
            yield block
            block = afile.read(blocksize)

## Validate the current filepath structure and contents match the checksum_map contents
def validate_checksum_map(validate_filepath_array, data_file, scan_base_directory_path, key):

	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")

	try:

		# Impoort the original application data from file
		original_filepath_array = import_data_from_file(data_file, key)

		# If a valid filepath array was build from data_file
		if original_filepath_array:

			# Define an array to keep track of changes if found
			report_array = []
			number_of_original_directories = len(original_filepath_array[0])
			number_of_directories_now = len(validate_filepath_array[0])
			number_of_original_files = len(original_filepath_array[1])
			number_of_files_now = len(validate_filepath_array[1])

			# Print a small set of initial data
			print "\nOriginal Filepath Details : "
			print "Folders : " + str(len(original_filepath_array[0])) + "\nFiles : " + str(len(original_filepath_array[1]))
			print "Current Filepath Details : "
			print "Folders : " + str(len(validate_filepath_array[0])) + "\nFiles : " + str(len(validate_filepath_array[1]))

			# Compare number of files and folders between original and current filestructure
			if number_of_original_directories != number_of_directories_now:
				report_array.append(("DIRECTORY COUNT MISMATCH", "Original: " + str(number_of_original_directories) + " Now: " + str(number_of_directories_now)))
			if number_of_original_files != number_of_files_now:
				report_array.append(("FILE COUNT MISMATCH", "Original: " + str(number_of_original_files) + " Now: " + str(number_of_files_now)))

			# Print each folder in original and current filpath_arrays
			print "\nOriginal Folders in Application:"
			# For each item in current filepath directory list, check if in original directory list
			for item in original_filepath_array[0]:
				print item.replace(scan_base_directory_path, "/")
				# Validate that directory is part of original application filestructure
				if item not in validate_filepath_array[0]:
					# If not, add line to report array
					report_array.append(("MISSING DIRECTORY", item))

			print "\nCurrent Folders in Application :"
			# For each item in current filepath directory list, check if in original directory list
			for item in validate_filepath_array[0]:
				print item.replace(scan_base_directory_path, "/")
				# Validate that directory is part of original application filestructure
				if item not in original_filepath_array[0]:
					# If not, add line to report array
					report_array.append(("UNMAPPED NEW DIRECTORY FOUND", item))

			# Print each file in original and current filpath_arrays
			print "\nOriginal Files in Application:"
			# For each item in current filepath file list, check if in original file list
			for item in original_filepath_array[1]:
				print item.replace(scan_base_directory_path, "/")
				# Validate that directory is part of original application filestructure
				if item not in validate_filepath_array[1]:
					# If not, add line to report array
					report_array.append(("MISSING FILE", item))

			print "\nCurrent Files in Application:"
			# For each item in current filepath file list, check if in original file list
			for item in validate_filepath_array[1]:
				print item.replace(scan_base_directory_path, "/")
				# Validate that directory is part of original application filestructure
				if item not in original_filepath_array[1]:
					# If not, add line to report array
					report_array.append(("UNMAPPED NEW FILE FOUND", item))

			# Print each file in original and current filpath_arrays
			print "\nOriginal Checksum Map of Application:"
			for i, item_original in enumerate(original_filepath_array[2]):
				print "FILENAME: " + original_filepath_array[1][i].replace(scan_base_directory_path, "/") + "\t\tCHECKSUM: " + item_original

			print "\nCurrent Checksum Map of Application:"
			# Validate each checksum between original map and current map
			for i, item_validate in enumerate(validate_filepath_array[2]):
				print "FILENAME: " + validate_filepath_array[1][i].replace(scan_base_directory_path, "/") + "\t\tCHECKSUM: " + item_validate
				# Validate the current checksum against the file checksum
				for j, item_original in enumerate(original_filepath_array[2]):
					# Check that filenames match and checksum match
					if validate_filepath_array[1][i] == original_filepath_array[1][j]:
						# Validate checksum of matching files
						if item_validate == item_original:
							pass
						# Case that validate file md5 checksum does not match exact file checksum in original map
						else:
							# If not the same, add to report
							report_array.append(("CHECKSUM MISMATCH", "\nCurrent file: " + validate_filepath_array[1][i].replace(scan_base_directory_path, "/") + "\t\tCHECKSUM = " + validate_filepath_array[2][i] + " \nOriginal File: " + original_filepath_array[1][i].replace(scan_base_directory_path, "/") + "\t\tCHECKSUM = " +  original_filepath_array[2][i]))

			# If report array is empty then add an OK message
			if len(report_array) == 0:
				report_array.append(("CHECKSUM OK", "Applicaion: " + scan_base_directory_path))
			# Print the completed validation message to stdout
			print '\nValidation of checksum map complete!'
			# Log completed validation message
			logger.info('Validation of checksum map complete.')

			return report_array

		# The file import did not work so return false
		else:
			return False

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Error validating checksum map: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error validating checksum map: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

## Import data from file_list
def import_data_from_file(data_file, key):

	try:
		# Define array to store original file data
		original_filepath_array = [[],[],[]]

		# Collect the checksum map stored in file to variable called original_filepath_array
		with open(data_file) as original_file:
			original_file_content = original_file.read()

		# Decrypt the file from encrypted format
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		decryptor = AES.new(key, mode, IV=IV)
		original_file_content = decryptor.decrypt(original_file_content).split("\n")

		# Check that the first line is the password correct confirmation
		# If the password confirmation is not correct, then return false
		if original_file_content[0] != "++++":
			print "Incorrect Password!"
			return False
		else:
			original_file_content.pop(0)

		# You may also want to remove whitespace characters like `\n` at the end of each line
		for item in original_file_content:

			# Strip whitespace and newlines
			item = item.strip()

			# Check for the character used to pad the encryption
			if item.endswith("@"):
				pass
			# If line from file is folder
			elif item.endswith('/'):
				original_filepath_array[0].append(item)
			# If line from file is file
			else:
				# Strip whitespace from line
				item = item.strip()
				# Split the line value by comma
				line_list = item.split(",")
				# append the filename and checksum into array
				original_filepath_array[1].append(line_list[0].strip())
				original_filepath_array[2].append(line_list[1].strip())
		# Return the array
		return original_filepath_array

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Error importing data from file: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error importing data from file: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

## Build report from array, wrirte to file and send email
def build_report_from_array(report_array, report_file, email_report_to_address_array, email_report, report_to_file, email_server_array, scan_base_directory_path):

	try:
		# Build header string
		header_string = "MD5 Checksum Report for application: " + scan_base_directory_path + " at " + time.strftime("%c")
		body_string = ""

		#print report_array
		# If the report has data in it
		if len(report_array) != 0:

			# Parse report_array into text string
			for item in report_array:
				body_string += item[0] + " - " + item[1] + "\n"

		# If report array is empty
		else:
			# Create a body string that says OK
			body_string = "Checksum Validated - OK!" + "\n"

		# Build several bodies of string for various output methods
		body_string_email = "\n" + header_string + "\n\n" + body_string
		body_string_stdout = "\n" + header_string + "\n\n" + body_string
		body_string_file = header_string + "\n" + body_string

		# Print the report string to stdout
		print body_string_stdout

		# Print report to file if required message sent
		if report_to_file:
			report_file = open(report_file, "a+")
			report_file.write(body_string_file)
			print "Report written to file!"

		# Email report if required flag set
		if email_report:
			# For each email address to send report to
			for email_report_to_address in email_report_to_address_array:
				# Call function to send a single email
				email_report_success = send_report_email(email_report_to_address, body_string_email, header_string, email_server_array)
				if email_report_success:
					print 'Success sending report by email to: ' + email_report_to_address
					logger.info('Success sending report by email to: ' + email_report_to_address)
				else:
					print 'Failed sending report by email!'
					logger.info('Failed sending report by email to: ' + email_report_to_address)

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Error building report: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error building report: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Send report by email to recipient
def send_report_email(email_report_to_address, body_string, header_string, email_server_array):

	try:
		# Prepare the message string
		report_message_text = """From: %s\nTo: %s\nSubject: %s\n\n%s
    	""" % (email_server_array['from_address'], email_report_to_address, header_string, body_string)

		# Send the message via our own SMTP server, but don't include the
		# envelope header.
		mail_server = smtplib.SMTP(email_server_array["host"], port = email_server_array["port"])
		mail_server.ehlo()
		mail_server.starttls()
		mail_server.login(email_server_array["username"], email_server_array["password"])
		mail_server.sendmail(email_server_array['from_address'], email_report_to_address, report_message_text)
		mail_server.close()
		return True

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Error sending report email: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Error sending report email: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

## Parses the command argument sys.arg into command set, also encrypt password for use
def build_command_arguments(argument_array, allowed_args_array, allowed_reset_args_array):

	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")

	try:
		# Create an array to store modified command line arguemnts
		command_arg = {}

		# Pop off the first element of array because it's the application filename
		argument_array.pop(0)
		# Check if argument array length is proper and help menu requested
		if len(argument_array) == 1 and ("-h" in argument_array or "-help" in argument_array):
			command_arg["command"] = "h"
			return command_arg


		# Check that the argument array is proper length (4)
		elif len(argument_array) >= 3 and len(argument_array) <= 6:
			# Find the password argument and take the password part and encrypt, attach as the second argument
			if "-p" in argument_array:
				try:
					# Calculate position of -p argument
					password_flag_position = argument_array.index("-p")
					# Pop the flag off the array
					argument_array.pop(password_flag_position)
					# Look for the password in the next position
					raw_password = argument_array[password_flag_position]
					# Pop the password string out of the argument array
					argument_array.pop(password_flag_position)
					# encrypt the raw_password into the form used for encryption
					key = hashlib.sha256(raw_password).digest()
					# Append the key back onto the end of the command line arguement array
					command_arg["password"] = key
				except Exception as e:
					# Collect the exception information
					exc_type, exc_obj, exc_tb = sys.exc_info()
					fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
					# Print the error
					print 'Failed to parse password argument: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
					# Log error with creating filepath
					logger.error('Failed to parse password argument: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
					return False

			# Find the password argument and take the password part and encrypt, attach as the second argument
			if "-f" in argument_array:
				try:
					# Calculate position of -f argument
					application_dirpath_flag_position = argument_array.index("-f")
					# Pop the flag off the array
					argument_array.pop(application_dirpath_flag_position)
					# Look for the application dirpath in the next position
					application_dirpath = argument_array[application_dirpath_flag_position]
					# Pop the password string out of the argument array
					argument_array.pop(application_dirpath_flag_position)
					# Append the dirpath back onto the end of the command line argument dictionary
					command_arg["application_filepath"] = application_dirpath
				except Exception as e:
					# Collect the exception information
					exc_type, exc_obj, exc_tb = sys.exc_info()
					fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
					# Print the error
					print 'Failed to parse application filepath argument: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
					# Log error with creating filepath
					logger.error('Failed to parse application filepath argument: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
					return False

			# Find the reset argument and take the mode
			# Do not pop off the -reset argument to maintain could validity
			if "-reset" in argument_array:
				try:
					# Calculate position of -f argument
					reset_flag_position = argument_array.index("-reset")
					# Look for the application dirpath in the next position
					# and append to command_arg
					command_arg["reset_mode"] = argument_array[reset_flag_position + 1]
					if command_arg['reset_mode'] not in allowed_reset_args_array:
						return False
					# Pop the reset mode string out of the argument array
					argument_array.pop(reset_flag_position + 1)
				except Exception as e:
					# Collect the exception information
					exc_type, exc_obj, exc_tb = sys.exc_info()
					fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
					# Print the error
					print 'Failed to parse reset mode argument: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
					# Log error with creating filepath
					logger.error('Failed to parse reset mode argument: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
					return False

		# If there is no password argument, then the command line is failed
		else:
			logger.warning("Command line argument entered incorrectly.")
			return False

		# For loop to modify elements and strip "-"
		if len(argument_array) ==  1:
			if argument_array[0] in allowed_args_array:
				command_arg['command'] = argument_array[0].replace('-', '')
		else:
			logger.warning("Command line argument entered incorrectly.")
			return False

		# The final array should always be list of length 2 to 4
		if len(command_arg) < 2 or len(command_arg) > 4:
			return False
		# Return the modified array of length is proper
		else:
			return command_arg

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Get the saved exclusion file for the application being validated
def get_logged_exclusion_file(exclusion_log_file):

	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")
	# Declare an array to accept the lines
	exclusion_set_array = []

	# Collect the exclusion set stored in file to array called exclusion_set_array
	if os.path.isfile(exclusion_log_file):
		with open(exclusion_log_file) as exclusion_log_file:
			exclusion_file_array = exclusion_log_file.readlines()
	# If no exclusion set is found, then return false
	else: return False

	# Strip all newline characters from items in array
	for item in exclusion_file_array:
		exclusion_set_array.append(item.strip())

	# Return the array of exclusion files
	#print exclusion_set_array
	return exclusion_set_array

# Create an exclusion file for the application being mapped
def create_exclusion_set(exclusion_file, exclusion_log_file):

	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")
	# Declare an array to accept the lines
	exclusion_set_array = []

	try:
		# Collect the exclusion set stored in file to array called exclusion_set_array
		with open(exclusion_file) as exclusion_file:
			exclusion_file_array = exclusion_file.readlines()

		# Add all non comment lines to the array
		for item in exclusion_file_array:
			# Ignore blank lines
			if item.strip() and item.strip()[0] != "#":
				exclusion_set_array.append(item.strip())

		#print exclusion_set_array
		# Write the exclusion set to file for reuse when validating
		exclusion_log_file = open(exclusion_log_file, "w")
		for item in exclusion_set_array:
			exclusion_log_file.write(item + "\n")
		exclusion_log_file.close()
		# Return the exclusion set array
		return exclusion_set_array

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print 'Failed to build exclusion set: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		logger.error('Failed to build exclusion set: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Check if there is a map data file for for the application path already
def check_app_map_exists(data_file):
	# Check if the data file path exists and return result.
	return os.path.isfile(data_file)

# Return the string of output for the help menu
def build_argument_output():
	argument_output = "Usage : checksum_validator.py [-map | -validate | -reset] [-p <password>] [-f /path/to/appication/]\n"
	argument_output += "-h, -help : print help menu\n"
	argument_output += "-map : create a checksum map for the application folder directory structure and files\n"
	argument_output += "-reset <mode> : delete map as speficied by <mode> [map, exclusion, all]\n"
	argument_output += "-validate : validate the application file contents and return if any changes exist\n"
	argument_output += "-a <dirpath> : specify the application directory path\n"
	argument_output += "-p <password> : enter the password required to encrypt or decrypt the data payload\n"
	return argument_output

# Setup logging
def setup_logger(log_file):
	logger = logging.getLogger('MD5_checksum_validator')
	log_handler = logging.FileHandler(log_file)
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	log_handler.setFormatter(formatter)
	logger.addHandler(log_handler)
	logger.setLevel(logging.DEBUG)

## Main Function Starts Here ##
if __name__ == '__main__':

	## Declare required variables
	# Set current working directory
	working_directory = os.getcwd()
	# Set current datetime
	current_time_string = str(datetime.datetime.now()).replace(" ", "_").split(".")[0]
	# Application Name used in report
	application_name = "Test Application"
	# set the base directory of the appliation to scan and validate
	scan_base_directory_path = "/Users/development/Documents/Software/scripts/python/checksum_validator/test_suite"
	# sets the filepath for the encrypted data file
	data_file = working_directory + "/log/" + scan_base_directory_path[1:len(scan_base_directory_path)].replace("/", "_") + "_data"
	exclusion_file = working_directory + "/exclusion.cnf"
	exclusion_log_file = working_directory + "/log/" + scan_base_directory_path[1:len(scan_base_directory_path)].replace("/", "_") + "_exclusion"
	log_file = working_directory + "/log/checksum_validator.log"
	report_file = working_directory + "/log/" + scan_base_directory_path[1:len(scan_base_directory_path)].replace("/", "_") + "_" + current_time_string + "_report.txt"
	email_report_to_address_array = ["user@emailaddress.ca", "userl@emailaddress2.com"]
	email_server_array = {
		"host" : "smtp.mailserver.com",
		"port" : "587",
		"username" : "user@mailserver.com",
		"password" : "password",
		"from_address" : "user@mailserver.com"}
	allowed_args_array = ["-map", "-validate", "-reset", "-h", "-help"]
	allowed_reset_args_array = ["map", "exclusion", "all"]
	report_errors_array = []
	email_report = False
	report_to_file = True

	## Run function to setup logger
	setup_logger(log_file)
	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")

	## Perform analysis of command line args into another array
	command_arg = build_command_arguments(sys.argv, allowed_args_array, allowed_reset_args_array)

	## Check return from command line arg bulder and if no command line args
	## print error message and menu
	if command_arg == False or ("command" in command_arg and command_arg['command'] == "h"):
		if command_arg == False:
			print "command argument error...."

		## Print out full argument help menu
		print build_argument_output()

	## If the command arg has been created successfully continue with the application
	else:

		# Pass the application filepath argument to scan_base_directory_path if exists
		if "application_filepath" in command_arg:
			scan_base_directory_path = command_arg["application_filepath"]

		# Make sure that the application filepath has a `/` at the end
		if scan_base_directory_path[len(scan_base_directory_path) - 1] != "/":
			scan_base_directory_path += "/"

		## reset the create_checksum_map and reconfigure checksum.
		if command_arg["command"] == "reset":

			# Print sdout and log start to reset map for that application directory
			print "Resetting existing map for the application directory... " + scan_base_directory_path
			logger.info('Resetting existing map for the application directory... ' + scan_base_directory_path)

			# Check the password integrity
			password_integrity = check_password_integrity(working_directory, scan_base_directory_path, command_arg['password'])
			if password_integrity:
				# Delete map file
				os.remove(working_directory + "/log/" + scan_base_directory_path.strip("/").replace("/", "_") + "_data")
				# Reset command args to include `map`
				command_arg['command'] = 'map'
			else:
				# Print sdout and log password failure to rest map for that application directory
				print "Failed to reset existing map for the application directory... " + scan_base_directory_path
				logger.info('Failed to reset existing map for the application directory... ' + scan_base_directory_path)

		## Pass the filepath_array to create_checksum_map
		if command_arg["command"] == 'map':

			# Print sdout and log start to check if existing map exists for that application directory
			print "Checking for existing map for the application directory... " + scan_base_directory_path
			logger.info('Checking for existing map for the application directory... ' + scan_base_directory_path)
			existing_checksum_map = check_app_map_exists(data_file)
			if existing_checksum_map == False:
				# Print stdout and log to start building exclusion set
				print "Building exclusion set of directories/files to ignore..."
				logger.info('Building exclusion set from file pointer : ' + exclusion_file)
				exclusion_set_array = create_exclusion_set(exclusion_file, exclusion_log_file)
				if exclusion_set_array:
					# Print and log success of building exclusion set
					print "Exclusion set created successfully!"
					logger.info('Exclusion set created successfully.')

					## Print a message to user to confirm initialization of application filemap bulding
					print "Staring to map application directory path..."

					# Create a filepath array to checksum
					filepath_array = create_file_map(scan_base_directory_path, exclusion_set_array)
					if filepath_array:
						## Print a message to user to confirm successful build of filepath map
						print "Filepath read successfully!"
						# Log info successs creating filepath map
						logger.info('Success creating filepath map: ' + scan_base_directory_path)
						## Create a checksum map for the file array
						create_checksum_map(filepath_array, data_file, scan_base_directory_path, command_arg["command"], command_arg["password"])

						## Print a message to user to confirm successful build of checksum map
						print "Checksum map created successfully!"
						# Log info successs creating checksum map
						logger.info('Success creating checksum map.')
					else:
						print "There was an error creating filepath or checksum!" + scan_base_directory_path
						# Log error with creating filepath
						logger.error('Error creating filepath or checksum: ' + scan_base_directory_path)
			else:
				print "An existing checksum map for that application directory already exists.\nYou must reset it if you want to create a new one or validate it."
				# Log error that checksum map for application already exists.
				logger.error('Attempt to build checksum map for application that already exists: ' + scan_base_directory_path)

		elif command_arg["command"] == 'validate':

			## Print a message to user to confirm initialization of application validation
			print "Staring to validate application integrity... " + scan_base_directory_path
			# Log info successs creating filepath map
			logger.info('Staring to validate application integrity ' + scan_base_directory_path)

			# Retrieve the exclusion set from logged record
			exclusion_set_array = get_logged_exclusion_file(exclusion_log_file)
			# If exclusion set could be built
			if exclusion_set_array:
				# Create a filepath array to
				filepath_array = create_file_map(scan_base_directory_path, exclusion_set_array)
				if filepath_array:
					## Print a message to user to confirm successful build of filepath map
					print "Filepath read successfully!"
					# Log info successs creating filepath map
					logger.info('Success creating filepath map: ' + scan_base_directory_path)

					## Create a checksum map for the file array
					validate_filepath_array = create_checksum_map(filepath_array, data_file, scan_base_directory_path, command_arg["command"])
					if validate_filepath_array:
						## Print a message to user to confirm successful build of checksum map
						print "Checksum map created successfully!"
						# Log info successs creating checksum map
						logger.info('Success creating checksum map: ' + scan_base_directory_path)

						## Validate the checksum map
						report_array = validate_checksum_map(validate_filepath_array, data_file, scan_base_directory_path, command_arg["password"])
						if report_array:
							## Print a message to user to confirm successful build of checksum map
							print "Validation completed successfully!"
							# Log info successs creating checksum map
							logger.info('Validation completed successfully: ' + scan_base_directory_path)

							# Output report to desired locations
							build_report_from_array(report_array, report_file, email_report_to_address_array, email_report, report_to_file, email_server_array, scan_base_directory_path)
							# Print the completed report message to stdout
							print 'Report build completed successfully!'
							# Log completed report message
							logger.info('Report build complete.')

			# If exclusion set could not be built, then no map exists
			else:
				print "No application map found for : " + scan_base_directory_path
