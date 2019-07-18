#!/usr/local/bin/node
'use strict';
/**
* @file encrypt-notes.js
* @brief Encrypts the notes.
* @author Anadian
* @copyright 	Copyright 2019 Canosw
	Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software 
without restriction, including without limitation the rights to use, copy, modify, 
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
permit persons to whom the Software is furnished to do so, subject to the following 
conditions:
	The above copyright notice and this permission notice shall be included in all copies 
or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//Dependencies
	//Internal
	//Standard
	const Crypto = require('crypto');
	const FileSystem = require('fs');
	const Utility = require('util');
	const Path = require('path');
	//External
	const GetStream = require('get-stream');
	const SaltFile = require('salt-file');
	const Inquirer = require('inquirer');
	const MultiHashes = require('multihashes');
	const MultiBase = require('multibase');

//Constants
const FILENAME = 'encrypt-notes.js';
const MODULE_NAME = 'EncryptNotes';
var PROCESS_NAME = '';
if(require.main === module){
	PROCESS_NAME = 'encrypt-notes';
} else{
	PROCESS_NAME = process.argv0;
}

//Global Variables
var Logger = { 
	log: () => {
		return null;
	}
};
//Functions
function Logger_Set( logger ){
	var _return = [1,null];
	const FUNCTION_NAME = 'Logger_Set';
	//Variables
	var function_return = [1,null];

	//Parametre checks
	if( typeof(logger) === 'object' ){
		if( logger === null ){
			logger = { 
				log: () => {
					return null;
				}
			};
		}
	} else{
		_return = [-2,'Error: param "logger" is not an object.'];
	}

	//Function
	if( _return[0] === 1 ){
		Logger = logger;
		_return = [0,null];
	}

	//Return
	return _return;
}
/**
* @fn EncNotes_DecipheredObject_New
* @brief Creates a new DecipheredObject from file information.
* @param basename
*	@type String
*	@brief The basename of file/DecipheredObject.
*	@default null
* @param data
*	@type Buffer:Object
*	@brief The data, as a Buffer, of the DecipheredObject.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncNotes_DecipheredObject_New( basename, data ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncNotes_DecipheredObject_New';
	//Variables
	var deciphered_object = {
		basename_string: '',
		multibase_digest: null,
		deciphered_data_buffer: null
	};
	var hash = null;
	var sha256_digest = null;
	var multihash_digest = null;
	var multibase_disgest = null;
	var buffer_offset = 0;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Entered.'});
	//Parametre checks
	if( basename == null || typeof(basename) !== 'string' ){
		_return = [-2, 'Error: param "basename" is either null or not a string.'];
	}
	if( data == null || Buffer.isBuffer(data) === false){
		_return = [-3, 'Error: param "data" is either null or not a Buffer.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		if( basename.length < 255 ){
			deciphered_object.basename_string = basename;
			hash = Crypto.createHash('sha256');
			hash.update( deciphered_object.basename_string, 'utf8' );
			sha256_digest = hash.digest();
			multihash_digest = MultiHashes.encode( sha256_digest, 'sha2-256' );
			deciphered_object.multibase_digest = MultiBase.encode( 'base64urlpad', multihash_digest );
			try{
				deciphered_object.deciphered_data_buffer = Buffer.alloc( (1 + deciphered_object.basename_string.length + data.length) );
				buffer_offset = deciphered_object.deciphered_data_buffer.writeUInt8( deciphered_object.basename_string.length, 0 );
				buffer_offset += deciphered_object.deciphered_data_buffer.write( deciphered_object.basename_string, buffer_offset, deciphered_object.basename_string.length, 'utf8' );
				buffer_offset += data.copy( deciphered_object.deciphered_data_buffer, buffer_offset );
				if( buffer_offset === deciphered_object.deciphered_data_buffer.length ){
					_return = [0, deciphered_object];
				} else{
					_return = [-16, 'Error: "buffer_offset" is not equal to "deciphered_object.deciphered_data_buffer.length"'];
				}
			} catch(error){
				_return = [-8, Utility.format('Buffer.alloc threw: %s', error)];
			}
		} else{
			_return = [-4, 'Error: "input_filepath_basename" is too long; "input_filepath_basename" needs to be less than 255 characters long.'];
		}
	}
	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('Return code: %d', _return[0])}); //Do not log deciphered_object.
	return _return;
}
/**
* @fn EncNotes_DecipheredObjectFromFile
* @brief Creates a new DecipheredObject from the file at the given filepath.
* @param filepath
*	@type String
*	@brief The path to the file to be turned into a DecipheredObject.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncNotes_DecipheredObjectFromFile( filepath ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncNotes_DecipheredObjectFromFile';
	//Variables
	var filedata_buffer = null;
	var file_basename_string = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Entered.'});
	//Parametre checks
	if( filepath == null || typeof(filepath) !== 'string' ){
		_return = [-2, 'Error: param "filepath" is either null or not a string.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		try{
			filedata_buffer = FileSystem.readFileSync( filepath );
			try{
				file_basename_string = Path.basename( filepath );
				function_return = EncNotes_DecipheredObject_New( file_basename_string, filedata_buffer );
				if( function_return[0] === 0 ){
					_return = [0, function_return[1]];
				} else{
					_return = [function_return[0], 'EncNotes_DecipheredObject_New: '+function_return[1]];
				}
			} catch(error){
				_return = [-8, Utility.format('Path.basename threw: %s', error)];
			}
		} catch(error){
			_return = [-4, Utility.format('FileSystem.readFileSync threw: %s', error)];
		}
	}
	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('Return code: %d', _return[0])});
	return _return;
}

/**
* @fn EncNotes_CipheredObjectFromDecipheredObject
* @brief Create a CipheredObject from a given DecipheredObject and SecretKeyObject.
* @param secret_keyobject
*	@type SecretKeyObject:Object
*	@brief The Secret KeyObject to be used for the encryption.
*	@default null
* @param deciphered_object
*	@type DecipheredObject:Object
*	@brief The DecipheredObject to be encrypted.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncNotes_CipheredObjectFromDecipheredObject( secret_keyobject, deciphered_object ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncNotes_CipheredObjectFromDecipheredObject';
	//Variables
	var iv_buffer = null;
	var cipher = null;
	var ciphered_object = {
		multibase_digest: null,
		ciphered_data_buffer: null
	};
	var encrypted_string = '';
	var encrypted_buffer = null;
	var buffer_offset = 0;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Entered.'}); //Do not log secret_keyobject or deciphered_object!
	//Parametre checks
	if( secret_keyobject == null || typeof(secret_keyobject) !== 'object' ){
		_return = [-2, 'Error: param "secret_keyobject" is either null or not an object.'];
	}
	if( deciphered_object == null || typeof(deciphered_object) !== 'object' ){
		_return = [-3, 'Error: param "deciphered_object" is either null or not an object.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		if( deciphered_object.multibase_digest != null ){
			ciphered_object.multibase_digest = deciphered_object.multibase_digest;
			try{
				iv_buffer = Crypto.randomBytes(16);
				try{
					cipher = Crypto.createCipheriv( 'aes-256-ofb', secret_keyobject, iv_buffer );
					if( cipher != null && typeof(cipher) === 'object' ){
						if( deciphered_object.deciphered_data_buffer != null && Buffer.isBuffer(deciphered_object.deciphered_data_buffer) === true ){
							//Dispite what the documentation claims, cipher.update and ciphere.final default to returning a UTF8 string and not a buffer, so I specified 'utf8' explicitly to alleviate any ambiguity.
							encrypted_string = cipher.update( deciphered_object.deciphered_data_buffer, 'utf8', 'utf8' );
							encrypted_string += cipher.final( 'utf8' );
							//Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('encrypted_buffer: %o %s', encrypted_buffer, typeof(encrypted_buffer))});
							if( encrypted_string != null && typeof(encrypted_string) === 'string' ){
								encrypted_buffer = Buffer.from( encrypted_string, 'utf8' );
								if( encrypted_buffer != null && Buffer.isBuffer(encrypted_buffer) === true ){
									try{
										ciphered_object.ciphered_data_buffer = Buffer.alloc( (1 + iv_buffer.length + encrypted_buffer.length) );
										buffer_offset = ciphered_object.ciphered_data_buffer.writeUInt8( iv_buffer.length, 0 );
										buffer_offset += iv_buffer.copy( ciphered_object.ciphered_data_buffer, buffer_offset );
										buffer_offset += encrypted_buffer.copy( ciphered_object.ciphered_data_buffer, buffer_offset );
										if( buffer_offset === ciphered_object.ciphered_data_buffer.length ){
											_return = [0, ciphered_object];
										} else{
											_return = [-1024, 'Error: "buffer_offset" is not equal to "ciphered_object.ciphered_data_buffer.length"'];
										}
									} catch(error){
										_return = [-512, Utility.format('Buffer.alloc threw: %s', error)];
									}
								} else{
									_return = [-256, 'Error: "encrypted_buffer" is either null or not a Buffer.'];
								}
							} else{
								_return = [-128, 'Error: "encrypted_string" is either null or not a string.'];
							}
						} else{
							_return = [-64, 'Error: "deciphered_object.deciphered_data_buffer" is either null or not a Buffer.'];
						}
					} else{
						_return = [-32, 'Error: "cipher" is either null or not an object.'];
					}
				} catch(error){
					_return = [-16, Utility.format('Crypto.createCipheriv threw: %s', error)];
				}
			} catch(error){
				_return = [-8, Utility.format('Crypto.randomBytes threw: %s', error)];
			}
		} else{
			_return = [-4, 'Error: "deciphered_object.multibase_digest" is either null or undefined.'];
		}
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('Return code: %d', _return[0])}); //Do not log ciphered_object.
	return _return;
}
/**
* @fn EncNotes_FileFromCipheredObject
* @brief Writes a file based on a given CipheredObject.
* @param ciphered_object
*	@type CipheredObject:Object
*	@brief The CipheredObject to be written to a file.
*	@default null
* @param output_directory
*	@type String
*	@brief The directory to write the file to.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncNotes_FileFromCipheredObject( ciphered_object, output_directory ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncNotes_FileFromCipheredObject';
	//Variables
	var filename_string = '';
	var filedata_buffer = null;
	var output_path = '';


	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Entered.'});
	//Parametre checks
	if( ciphered_object == null || typeof(ciphered_object) !== 'object' ){
		_return = [-2, 'Error: param "ciphered_object" is either null or not an object.'];
	} else{
		if( ciphered_object.multibase_digest != null && Buffer.isBuffer(ciphered_object.multibase_digest) === true ){
			filename_string = ciphered_object.multibase_digest.toString('utf8');
		} else{
			_return = [-3, 'Error: property "multibase_digest" of "ciphered_object" is either null or not a Buffer.'];
		}
		if( ciphered_object.ciphered_data_buffer != null && Buffer.isBuffer(ciphered_object.ciphered_data_buffer) ){
			filedata_buffer = ciphered_object.ciphered_data_buffer;
		} else{
			_return = [-4, 'Error: "ciphered_object.ciphered_data_buffer" is either null or not a Buffer.'];
		}
	}
	if( output_directory == null ){
		output_directory = '.';
	} else if( typeof(output_directory) !== 'string' ){
		_return = [-5, 'Error: param "output_directory" is not a string.'];
	}

	
	//Function
	if( _return[0] === 1 ){
		try{
			output_path = Path.join( output_directory, filename_string );
			try{
				FileSystem.writeFileSync( output_path, filedata_buffer, { encoding: null, mode: 416 } );
				_return = [0,null];
			} catch(error){
				_return = [-16, Utility.format('FileSystem.writefileSync threw: %s', error)];
			}
		} catch(error){
			_return  = [-8, Utility.format('Path.join threw: %s', error)];
		}
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}
/**
* @fn EncNotes_CipheredObjectFromFile
* @brief Creates a CipheredObject from the encrypted file at the given path.
* @param filepath
*	@type String
*	@brief The path of the encrypted file.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncNotes_CipheredObjectFromFile( filepath ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncNotes_CipheredObjectFromFile';
	//Variables
	var basename_string = '';
	var file_buffer = null;
	var ciphered_object = {
		multibase_digest: null,
		ciphered_data_buffer: null
	};


	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	if(	filepath == null || typeof(filepath) !== 'string' ){
		_return = [-2, 'Error: param "filepath" is either null or not a string.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		try{
			basename_string = Path.basename( filepath );
			try{
				ciphered_object.multibase_digest = Buffer.from( basename_string, 'utf8' );
				try{
					file_buffer = FileSystem.readFileSync( filepath );
					if( file_buffer != null && Buffer.isBuffer(file_buffer) === true ){
						ciphered_object.ciphered_data_buffer = file_buffer;
						_return = [0, ciphered_object];
					} else{
						_return = [-32, 'Error: "file_buffer" is either null or not a Buffer.'];
					}
				} catch(error){
					_return = [-16, Utility.format('FileSystem.readFileSync threw: %s', error)];
				}
			} catch(error){
				_return = [-8, Utility.format('Buffer.from threw: %s', error)];
			}
		} catch(error){
			_return = [-4, Utility.format('Path.basename threw: %s', error)];
		}
	}


	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}


/**
* @fn EncNotes_DecipheredObjectFromCipheredObject
* @brief Create a DecipheredObject from a given cipheredObject and SecretKeyObject.
* @param secret_keyobject
*	@type SecretKeyObject:Object
*	@brief The Secret KeyObject to be used for the decryption.
*	@default null
* @param ciphered_object
*	@type CipheredObject:Object
*	@brief The CipheredObject to be decrypted.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncNotes_DecipheredObjectFromCipheredObject( secret_keyobject, ciphered_object ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncNotes_DecipheredObjectFromCipheredObject';
	//Variables
	var iv_buffer_length = null;
	var iv_buffer = null;
	var decipher = null;
	var deciphered_object = {
		basename_string: null,
		multibase_digest: null,
		deciphered_data_buffer: null
	};
	var ciphertext_length = null;
	var ciphertext_buffer = null;
	var decrypted_string = '';
	var decrypted_buffer = null;
	var buffer_offset = 0;
	var basename_length = null;
	var basename_buffer = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Entered.'}); //Do not log secret_keyobject or ciphered_object!
	//Parametre checks
	if( secret_keyobject == null || typeof(secret_keyobject) !== 'object' ){
		_return = [-2, 'Error: param "secret_keyobject" is either null or not an object.'];
	}
	if( ciphered_object == null || typeof(ciphered_object) !== 'object' ){
		_return = [-3, 'Error: param "ciphered_object" is either null or not an object.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		if( ciphered_object.multibase_digest != null ){
			deciphered_object.multibase_digest = ciphered_object.multibase_digest;
			iv_buffer_length = ciphered_object.ciphered_data_buffer.readUInt8( 0 );
			try{
				iv_buffer = Buffer.alloc( iv_buffer_length );
				buffer_offset = (1 + ciphered_object.ciphered_data_buffer.copy( iv_buffer, 0, 1, iv_buffer_length ));
				ciphertext_length = (ciphered_object.ciphered_data_buffer.length - buffer_offset);
				try{
					ciphertext_buffer = Buffer.alloc( ciphertext_length );
					buffer_offset += ciphered_object.ciphered_data_buffer.copy( ciphertext_buffer, 0, buffer_offset );
					if( buffer_offset === ciphered_object.ciphered_data_buffer.length ){
						decipher = Crypto.createDecipheriv( 'aes-256-ofb', secret_keyobject, iv_buffer );
						if( decipher != null && typeof(decipher) === 'object' ){
							decrypted_string = decipher.update( ciphertext_buffer, 'utf8', 'utf8' );
							decrypted_string += decipher.final( 'utf8' );
							if( decrypted_string != null && typeof(decrypted_string) === 'string' ){
								Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('Decrypted string: %s', decrypted_string)});
								decrypted_buffer = Buffer.from(decrypted_string, 'utf8');
								if( decrypted_buffer != null && Buffer.isBuffer(decrypted_buffer) ){
									basename_length = decrypted_buffer.readUInt8( 0 );
									try{
										basename_buffer = Buffer.alloc( basename_length );
										buffer_offset = (1 + decrypted_buffer.copy( basename_buffer, 0, 1 ));
										deciphered_object.basename_string = basename_buffer.toString( 'utf8' );
										try{
											deciphered_object.deciphered_data_buffer = Buffer.alloc( decrypted_buffer.length );
											buffer_offset = decrypted_buffer.copy( deciphered_object.deciphered_data_buffer, 0 );
											if( buffer_offset === deciphered_object.deciphered_data_buffer.length ){
												_return = [0, deciphered_object];
											} else{
												_return = [-2048, 'Error: "buffer_offset" is not equal to "deciphered_object.deciphered_data_buffer.length"'];
											}
										} catch(error){
											_return = [-1024, Utility.format('Buffer.alloc threw: %s', error)];
										}
									} catch(error){
										_return = [-512, Utility.format('Buffer.alloc threw: %s', error)];
									}
								} else{
									_return = [-256, 'Error: "decrypted_buffer" is either null or not a string.'];
								}
							} else{
								_return = [-128, 'Error: "decrypted_string" is either null or not a string.'];
							}
						} else{
							_return = [-64, 'Error: "decipher" is either null or not an object.'];
						}
					} else{
						_return = [-32, 'Error: "buffer_offset" is not equal to "ciphered_object.ciphered_data_buffer.length"'];
					}
				} catch(error){
					_return = [-16, Utility.format('Buffer.alloc threw: %s', error)];
				}
			} catch(error){
				_return = [-8, Utility.format('Buffer.alloc threw: %s', error)];
			}
		} else{
			_return = [-4, 'Error: "ciphered_object.multibase_digest" is either null or undefined.'];
		}
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('Return code: %d', _return[0])}); //Do not log deciphered_object.
	return _return;
}
/**
* @fn EncNotes_FileFromDecipheredObject
* @brief Writes a DecipheredObject to a file.
* @param deciphered_bject
*	@type DecipheredObject:Object
*	@brief The DecipheredObject to write to the file system.
*	@default null
* @param output_directory
*	@type String
*	@brief The directory to write the file to.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncNotes_FileFromDecipheredObject( deciphered_object, output_directory ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncNotes_FileFromDecipheredObject';
	//Variables
	var filename = '';
	var file_buffer = null;
	var output_path = '';

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	if( deciphered_object == null || typeof(deciphered_object) !== 'object' ){
		_return = [-2, 'Error: param "deciphered_object" is either null or not an object.'];
	} else if( deciphered_object.basename_string == null || typeof(deciphered_object.basename_string) !== 'string' ){
		_return = [-3, 'Error: "deciphered_object.basename_string" is either null or not a string.'];
	} else if( deciphered_object.deciphered_data_buffer == null || Buffer.isBuffer(deciphered_object.deciphered_data_buffer) !== true ){
		_return = [-4, 'Error: "deciphered_object.deciphered_data_buffer" is either null or not a Buffer.'];
	}
	if( output_directory == null ){
		output_directory = '.';
	} else if( typeof(output_directory) !== 'string' ){
		_return = [-5, 'Error: param "output_directory" is not a string.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		try{
			output_path = Path.join( output_directory, deciphered_object.basename_string );
			try{
				FileSystem.writeFileSync( output_path, deciphered_object.deciphered_data_buffer );
				_return = [0,null];
			} catch(error){
				_return = [-16, Utility.format('FileSystem.writeFileSynce threw: %s', error)];
			}
		} catch(error){
			_return = [-8, Utility.format('Path.join threw: %s', error)];
		}
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}


/**
* @fn EncryptFile
* @brief Encrypts the given file with the given secret key and writes the encrypted file to the given target directory.
* @param secret_key
*	@type SecretKey:Object
*	@brief The secret key to generate the cipher with.
*	@default null
* @param input_filepath
*	@type String
*	@brief The file to be encrypted.
*	@default null
* @param output_directory
*	@type String
*	@brief The directory the encrypted file will be stored.
*	@default 'enc'
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncryptFile( secret_key, input_filepath, output_directory ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncryptFile';
	//Variables
	var input_filepath_basename = null;
	var input_filedata = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Entered.'}); //Do not log secret_key.
	//Parametre checks
	if( secret_key == null || typeof(secret_key) !== 'object' ){
		_return = [-2, 'Error: param "secret_key" is either null or not an object.'];
	}
	if( input_filepath == null || typeof(input_filepath) !== 'string' ){
		_return = [-3, 'Error: param "input_filepath" is either null or not a string.'];
	}
	if( output_directory == null ){
		output_directory = 'enc';
	} else if( typeof(output_directory) !== 'string' ){
		_return = [-4, 'Error: param "output_directory" is not a string.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		/*function_return = EncNotes_DecipheredObjectFromFile( filepath );
		if( function_return[0] === 0 ){
			function_return = EncNotes_CipheredObjectFromDecipheredObject( secret_keyobject, function_return[1] );
			if( function_return[0] === 0 ){
				function_return = EncNotes_FileFromCipheredObject( function_return[1], 'enc' );
				if( function_return[0] === 0 ){
					function_return = EncNotes_CipheredObjectFromFile( filepath );
					if( function_return[0] === 0 ){
						function_return = EncNotes_DecipheredObjectFromCipheredObject( secret_keyobject, function_return[1] );
						if( function_return[0] === 0 ){
							function_return = EncNotes_FileFromDecipheredObject( function_return[1], 'unenc' );
						}
					}
				}
			}
		}
	}

												try{
													output_filepath = Path.join( output_directory, multibase_digest );
													try{
														FileSystem.writeFileSync( output_filepath, final_buffer, { encoding: null, mode: 416 } );
														_return = [0,null];
													} catch(error){
														_return = [-16384, Utility.format('FileSystem.writeFileSync threw: %s', error)];
													}
												} catch(error){
													_return = [-8192, Utility.format('Path.join threw: %s', error)];
												}
											} else{
												_return = [-4096, 'Error: "buffer_offset" is not equal to "final_buffer.length"'];
											}
										} catch(error){
											_return = [-2048, Utility.format('Buffer.alloc threw: %s', error)];
										}
									} else{
										_return = [-1024, 'Error: "ciphered_buffer" is either null or not a buffer.'];
									}
								} else{
									_return = [-512, 'Error: "cipher" is either null or not an object.'];
								}
							} catch(error){
								_return = [-256, Utility.format('Crypto.randomBytes threw: %s', error)];
							}
						} else{
							_return = [-128, 'Error: "buffer_offset" is not equal to "to_be_ciphered_buffer.length"'];
						}
					} catch(error){
						_return = [-64, Utility.format('Buffer.alloc threw: %s', error)];
					}
				} catch(error){
					_return = [-32, Utility.format('FileSystem.readFileSync threw: %s', error)];
				}
			} else{
				_return = [-16, 'Error: "input_filepath_basename" is too long; "input_filepath_basename" needs to be less than 255 characters long.'];
			}
		} catch(error){
			_return = [-8, Utility.format('Path.basename threw: %s', error)];
		}*/
	}
	if( _return[0] !== 0 ){
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'error', message: Utility.format('%o', _return)});
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}
/**
* @fn EncryptDirectory
* @brief Encrypts the given input directory with the given secret key.
* @param secret_keyobject
*	@type SecretKeyObject:Object
*	@brief The secret keyobject to be used for the encryption.
*	@default null
* @param input_directory
*	@type String
*	@brief The directory to be read and encrypted.
*	@default 'unenc'
* @param output_directory
*	@type String
*	@brief The directory the encrypted files will be written to.
*	@default 'enc'
* @param recursive
*	@type Boolean
*	@brief Whether to recursive encrypt any sub-directories encountered.
*	@default false
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function EncryptDirectory( secret_keyobject, input_directory, output_directory, recursive ){
	var _return = [1,null];
	const FUNCTION_NAME = 'EncryptDirectory';
	//Variables
	var directory_entries = null;
	var error_string = '';
	var loop_error_string = '';
	var input_filepath = '';
	var input_subdirectory = null;
	var output_subdirectory = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Entered.'}); //Do not log secret_keyobject.
	//Parametre checks
	if( secret_keyobject == null || typeof(secret_keyobject) !== 'object' ){
		_return = [-2, 'Error: param "secret_keyobject" is either null or not an object.'];
	}
	if( input_directory == null ){
		input_directory = 'unenc';
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'warn', message: 'param "input_directory" was null so it has been set to the default: '+input_directory});
	} else if( typeof(input_directory) !== 'string' ){
		_return = [-3, 'Error: param "input_directory" is not a string.'];
	}
	if( output_directory == null ){
		output_directory = 'enc';
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'warn', message: 'param "output_directory" was null so it has been set to the default: '+output_directory});
	} else if( typeof(output_drectory) !== 'string' ){
		_return = [-4, 'Error: param "output_directory" is not a string.'];
	}
	if( recursive == null ){
		recursive = false;
	} else if( typeof(recursive) !== 'boolean' ){
		_return = [-5, 'Error: param "recursive" is not a boolean.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		try{
			directory_entries = FileSystem.readdirSync( input_directory, { encoding: 'utf8', withFileTypes: true } );
			for( var i = 0; i < directory_entries.length; i++ ){
				if( directory_entries[i].isFile() === true ){
					try{ 
						input_filepath = Path.join( input_directory, directory_entries[i].name );
						function_return = EncryptFile( secret_keyobject, input_filepath, output_directory );
						if( function_return[0] !== 0 ){
							error_string = Utility.format('For loop index: %d: EncryptFile: %o', i, function_return);
						}
					} catch(error){
						error_string = Utility.format('For loop index: %d: Path.join threw: %s', i, error);
					}
				} else if( directory_entries[i].isDirectory() === true && recursive === true ){
					try{
						input_subdirectory = Path.join( input_directory, directory_entries[i].name );
						output_subdirectory = Path.join( output_directory, directory_entries[i].name );
						EncryptDirectory( secret_keyobject, input_subdirectory, output_subdirectory, true );
						if( function_return[0] !== 0 ){
							error_string = Utility.format('For loop index: %d: EncryptDirectory: %o', i, function_return);
						}
					} catch(error){
						error_string = Utility.format('For loop index: %d: Path.join threw: %s', i, error);
					}
				}
				if( error_string !== '' ){
					Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'error', message: error_string});
					loop_error_string += Utility.format(' %s |', error_string);
					error_string = '';
				}
			}
			if( loop_error_string === '' ){
				_return = [0,null];
			} else{
				_return = [-16, '"loop_error_string":'+loop_error_string];
			}
		} catch(error){
			_return = [-8, Utility.format('FileSystem.readdirSync threw: %s', error)];
		}
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}


/**
* @fn Input_InquirerPassword_Async
* @brief Handle the Inquirer prompt for the password asynchronously.
* @async true
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
async function Input_InquirerPassword_Async(){
	var _return = [1,null];
	const FUNCTION_NAME = 'Input_InquirerPassword_Async';
	//Variables
	var function_return = [1,null];
	var inquirer_questions = [
		{
			type: 'password',
			name: 'password',
			mask: '*'
		}
	];
	var inquirer_answer = null;
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	
	//Function
	try{
		inquirer_answer = await Inquirer.prompt( inquirer_questions );
		if( inquirer_answer.password != null && typeof(inquirer_answer.password) === 'string' ){
			_return = [0, inquirer_answer.password];
		} else{
			_return = [-8, 'Error: "inquirer_answer.password" is either null or not a string.'];
		}
	} catch(error){
		_return = [-4, Utility.format('Inquirer.prompt threw: %s', error)];
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('Return code: %d', _return[0])}); //DO NOT LOG PASSWORD!!
	return _return;
}
/**
* @fn Input_Scrypt_SecretKey_Get_Async
* @brief Asynchronously prompt for a password and generate a secret keyobject using the Scrypt key derivation function.
* @async true
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
async function Input_Scrypt_SecretKey_Get_Async(){
	var _return = [1,null];
	const FUNCTION_NAME = 'Input_Scrypt_SecretKey_Get_Async';
	//Variables
	var function_return = [1,null];
	var password = null;
	var scrypt_buffer = null;
	var secret_keyobject = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	
	//Function
	function_return = await Input_InquirerPassword_Async();
	if( function_return[0] === 0 ){
		password = function_return[1];
		function_return = SaltFile.LoadSaltFile();
		if( function_return[0] === 0 ){
			try{
				scrypt_buffer = Crypto.scryptSync( password, function_return[1], 32 );
				secret_keyobject = Crypto.createSecretKey( scrypt_buffer );
				if( secret_keyobject != null && typeof(secret_keyobject) === 'object' ){
					_return = [0, secret_keyobject];
				} else{
					_return = [-32, 'Error: "secret_keyobject" is either null or not an object.'];
				}
			} catch(error){
				_return = [-16,Utility.format('Crypto.scryptSync threw: %s', error)];
			}
		} else{
			_return = [function_return[0], 'SaltFile.LoadSaltFile: '+function_return[1]];
		}
	} else{
		_return = [function_return[0], 'Input_InquirerPassword_Async: '+function_return[1]];
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('Return code: %d', _return[0])}); //Do not log secret_keyobject!
	return _return;
}

/**
* @fn Input_STDIN_Get_Async
* @brief Asynchronously get stdin as a string.
* @async true
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
async function Input_STDIN_Get_Async(){
	var _return = [1,null];
	const FUNCTION_NAME = 'Input_STDIN_Get_Async';
	//Variables

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	
	//Function
	try{
		_return = [0, await GetStream( process.stdin, { encoding: 'utf8' } )];
	} catch(error){
		_return = [-4, Utility.format('GetStre.m threw: %s', error)];
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}
/**
* @fn Main_Test_Async
* @brief The test function.
* @async true
* @param options
*	@type Object
*	@brief Command-line options.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
async function Main_Test_Async( options ){
	var _return = [1,null];
	const FUNCTION_NAME = 'Main_Test_Async';
	//Variables
	var function_return = [1,null];
	var deciphered_object = null;
	var secret_keyobject = null;
	var ciphered_object = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	if( options == null || typeof(options) !== 'object' ){
		_return = [-2, 'Error: param "options" is either null or not an object.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		function_return = await Input_Scrypt_SecretKey_Get_Async();
		if( function_return[0] === 0 ){
			secret_keyobject = function_return[1];
			if( options.encrypt === true ){
				try{
					FileSystem.writeFileSync( 'unenc_test.txt', 'Some generic file for testing.', 'utf8' );
					function_return = EncNotes_DecipheredObjectFromFile( 'unenc_test.txt' );
					if( function_return[0] === 0 ){
						deciphered_object = function_return[1];
						function_return = EncNotes_CipheredObjectFromDecipheredObject( secret_keyobject, deciphered_object );
						if( function_return[0] === 0 ){
							function_return = EncNotes_FileFromCipheredObject( function_return[1] );
							if( function_return[0] === 0 ){
								_return = [0,null];
							} else{
								_return = [function_return[0], 'EncNotes_FileFromCipheredObject: '+function_return[1]];
							}
						} else{
							_return = [function_return[0], 'EncNotes_CipheredObjectFromDecipheredObject: '+function_return[1]];
						}
					} else{
						_return = [function_return[0], 'EncNotes_DecipheredObjectFromFile: '+function_return[1]];
					}
				} catch(error){
					_return = [-4, Utility.format('FileSystem.writeFileSync threw: %s', error)];
				}
			} 
			if( options.decrypt === true ){
				function_return = EncNotes_CipheredObjectFromFile('UEiA6o62_fweFtksZk6RRDp1uE2tMMsyMGmLMGWba3zpNVA==');
				if( function_return[0] === 0 ){
					function_return = EncNotes_DecipheredObjectFromCipheredObject( secret_keyobject, function_return[1] );
					if( function_return[0] === 0 ){
						function_return = EncNotes_FileFromDecipheredObject( function_return[1] );
						if( function_return[0] === 0 ){
							_return = [0,null];
						} else{
							_return = [function_return[0], Utility.format('EncNotes_FileFromDecipheredObject: %s', function_return[1])];
						}
					} else{
						_return = [function_return[0], Utility.format('EncNotes_DecipheredObjectFromCipheredObject: %s', function_return[1])];
					}
				} else{
					_return = [function_return[0], Utility.format('EncNotes_CipheredObjectFromFile: %s', function_return[1])];
				}
			}
		} else{
			_return = [function_return[0], 'Input_Scrypt_SecetKey_Get_Async: '+function_return[1]];
		}
	}

	if( _return[0] !== 0 ){
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'error', message: Utility.format('%o', _return)});
		process.exitCode = _return[0];
	}
	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}

/**
* @fn Main_EncNotes_Async
* @brief The asynchoronous main function for both encrypting and decrypting.
* @async true
* @param options
*	@type Object
*	@brief Command-line options.
*	@default null
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
async function Main_EncNotes_Async( options ){
	var _return = [1,null];
	const FUNCTION_NAME = 'Main_EncNotes_Async';
	//Variables
	var function_return = [1,null];
	var mode = 0; //1 encryption; 2 decryption.
	var input_data = '';
	var input_directory = '';
	var output_directory = '';
	var secret_keyobject = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	if(	options == null || typeof(options) !== 'object' ){
		_return = [-2, 'Error: param "options" is either null or not an object.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		if( options.stdin === true ){
			function_return = Input_STDIN_Get_Async();
			if( function_return[0] === 0 ){
				input_data = function_return[1];
			} else{
				_return = [function_return[0], 'Input_STDIN_Get_Async: '+function_return[1]];
			}
		} else{
			if( options.input != null && typeof(options.input) === 'string' ){
				try{
					function_return = FileSystem.statSync( options.input );
					if( function_return.isFile() === true ){
						try{
							input_data = FileSystem.readFileSync( options.input, 'utf8' );
						} catch(error){
							_return = [-32, Utility.format('FileSystem.readFileSync threw: %s', error)];
						}
					} else if( function_return.isDirectory() === true ){
						input_directory = options.input;
					} else{
						_return = [-16, 'Error: "options.input" is neither a file nor a directory.'];
					}
				} catch(error){
					_return = [-8, Utility.format('FileSystem.statSync threw: %s', error)];
				}
			} else{
				_return = [-4, 'Error: "options.input" is either null or not a string.'];
			}
		}
		function_return = await Input_Scrypt_SecretKey_Get_Async();
		if( function_return[0] === 0 ){
			secret_keyobject = function_return[1];
			if( typeof(input_directory) === 'string' && input_directory !== '' ){

			}
		} else{
			_return = [function_return[0], 'Input_Scrypt_SecretKey_Get_Async: '+function_return[1]];
		}
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}

//Exports and Execution
if(require.main === module){
	var _return = [1,null];
	const FUNCTION_NAME = 'MainExecutionFunction';
	//Dependencies
		//Internal
		//Standard
		//External
		const MakeDir = require('make-dir');
		const ApplicationLogWinstonInterface = require('application-log-winston-interface');
		const EnvPaths = require('env-paths');
		const CommandLineArgs = require('command-line-args');
		const CommandLineUsage = require('command-line-usage');
	//Constants
	const EnvironmentPaths = EnvPaths( PROCESS_NAME );
	const OptionDefinitions = [
		//UI
		{ name: 'help', alias: 'h', type: Boolean, description: 'Writes this help text to stdout.' },
		{ name: 'noop', alias: 'n', type: Boolean, description: 'Show what would be done without actually doing it.' },
		{ name: 'silent', alias: 's', type: Boolean, description: 'Silence all output to stderr.' },
		{ name: 'quiet', alias: 'q', type: Boolean, description: 'Only output warning and errors to stderr.' },
		{ name: 'verbose', alias: 'v', type: Boolean, description: 'Verbose output to stderr.' },
		{ name: 'version', alias: 'V', type: Boolean, description: 'Writes version information to stdout.' },
		//Mode
		{ name: 'encrypt', alias: 'e', type: Boolean, description: 'Encrypt the input.' },
		{ name: 'decrypt', alias: 'd', type: Boolean, description: 'Decrypt the input.' },
		{ name: 'test', alias: 't', type: Boolean, description: 'Run Main_Test_Async instead of the normal main.' },
		//Input
		{ name: 'stdin', alias: 'i', type: Boolean, description: 'Read input from stdin.' },
		{ name: 'input', alias: 'I', type: String, description: 'The path to the file to read input from.' },
		//Output
		{ name: 'stdout', alias: 'o', type: Boolean, description: 'Write output to stdout.' },
		{ name: 'output', alias: 'O', type: String, description: 'The name of the file to write output to.' },
		//Config
		{ name: 'config', alias: 'c', type: Boolean, description: 'Print configuration values and information to stdout.' },
		{ name: 'config-file', alias: 'C', type: String, description: 'Use the given config file instead of the default.' },
	];
	//Variables
	var function_return = [1,null];
	//Logger
	try{ 
		MakeDir.sync( EnvironmentPaths.log );
	} catch(error){
		console.error('MakeDir.sync threw: %s', error);
	}
	function_return = ApplicationLogWinstonInterface.InitLogger('debug.log', EnvironmentPaths.log);
	if( function_return[0] === 0 ){
		Logger_Set( function_return[1] );
	}
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'Start of execution block.'});
	//Options
	var Options = CommandLineArgs( OptionDefinitions );
	//Config
	//Main
	if(Options.help === true){
		const help_sections_array = [
			{
				header: 'encrypt-notes',
				content: 'Encrypts or decrypts notes.',
			},
			{
				header: 'Options',
				optionList: OptionDefinitions
			}
		];
		const help_message = CommandLineUsage(help_sections_array);
		console.log(help_message);
	}
	if(Options.quiet === true){
		Logger.real_transports.console_stderr.level = 'warn';
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'note', message: Utility.format('Logger: console_stderr transport log level is now: %s', Logger.real_transports.console_stderr.level)});
	}
	if(Options.silent === true){
		Logger.real_transports.console_stderr.enabled = 'emerg';
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'note', message: Utility.format('Logger: console_stderr transport log level is now: %s', Logger.real_transports.console_stderr.level)});
	}
	if(Options.verbose === true){
		Logger.real_transports.console_stderr.level = 'debug';
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'note', message: Utility.format('Logger: console_stderr transport log level is now: %s', Logger.real_transports.console_stderr.level)});
	}

	if( Options.test === true ){
		Main_Test_Async( Options );
	} else{
		if( Options.encrypt === true && Options.decrypt === true ){
			_return = [-2, 'Error: both "encrypt" and "decrypt" mode options were specified.'];
		} else if( Options.encrypt !== true && Options.decrypt !== true ){
			Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'warn', message: 'Neither "encrypt" nor "decrypt" mode options were specified.'});
		}

		if( _return[0] === 1 ){
			Main_EncNotes_Async( Options );
		} else{
			Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'error', message: Utility.format('%o', _return)});
			process.exitCode = _return[0];
		}
	}
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'End of execution block.'});
} else{
	exports.SetLogger = Logger_Set;
}
