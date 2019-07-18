#!/usr/local/bin/node
'use strict';
/**
* @file salt-file.js
* @brief Creates, stores and retrieves salt files for cryptographic modules.
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
	const Cryptography = require('crypto');
	const FileSystem = require('fs');
	const OperatingSystem = require('os');
	const Path = require('path');
	const Utility = require('util');
	//External

//Constants
const FILENAME = 'salt-file.js';
const MODULE_NAME = 'SaltFile';
var PROCESS_NAME = '';
if(require.main === module){
	PROCESS_NAME = 'salt-file';
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
* @fn SaltFile_New
* @brief Creates a new salt file at the given filepath.
* @param filepath
*	@type String
*	@brief The filepath of the new salt file.
*	@default ~/.ssh/enc-notes-saltfile
* @return <ARRAY>
*	@entry 0 
*		@retval 1 premature return.
*		@retval 0 on success.
*		@retval <0 on failure.
*	@entry 1
*		@retval <object> on success
*		@retval <error_message> on failure.
*/
function SaltFile_New( filepath ){
	var _return = [1,null];
	const FUNCTION_NAME = 'SaltFile_New';
	//Variables
	var salt_buffer = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	if( filepath == null ){
		try{
			filepath = Path.join( OperatingSystem.homedir(), '.ssh', 'salt' );
		} catch(error){
			_return = [-4, 'Path.join threw: '+error];
		}
	} else if( typeof(filepath) !== 'string' ){
		_return = [-2, 'Error: param "filepath" is either null or not a string.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		try{
			salt_buffer = Cryptography.randomBytes(1024);
			try{
				FileSystem.writeFileSync( filepath, salt_buffer, { encoding: 'utf8', mode: 384 } );
				_return = [0,null];
			} catch(error){
				_return = [-16, 'FileSystem.writeFileSync threw: '+error];
			}
		} catch(error){
			_return = [-8, 'Cryptography.randomBytes threw: '+error];
		}
	}
	if( _return[0] !== 0 ){
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'error', message: Utility.format('%o', _return)});
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned: ', _return)});
	return _return;
}
/**
* @fn SaltFile_Load
* @brief Loads the salt file at the given path a returns it as a buffer.
* @param filepath
*	@type String
*	@brief The filepath to load the salt buffer from.
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
function SaltFile_Load( filepath ){
	var _return = [1,null];
	const FUNCTION_NAME = 'SaltFile_Load';
	//Variables
	var salt_buffer = null;

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	if( filepath == null ){
		try{
			filepath = Path.join( OperatingSystem.homedir(), '.ssh', 'salt' );
		} catch(error){
			_return = [-4, 'Path.join threw: '+error];
		}
	} else if( typeof(filepath) !== 'string' ){
		_return = [-2, 'Error: param "filepath" is either null or not a string.'];
	}
	
	//Function
	if( _return[0] === 1 ){
		try{
			salt_buffer = FileSystem.readFileSync( filepath );
			if( salt_buffer != null && Buffer.isBuffer(salt_buffer) && salt_buffer.length === 1024 ){
				_return = [0,salt_buffer];
			}
		} catch(error){
			_return = [-8, 'FileSystem.readFileSync threw: '+error];
		}
	}
	if( _return[0] !== 0 ){
		Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'error', message: Utility.format('%o', _return)});
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned code: %d', _return[0])}); //Making sure to NOT log the actual salt data.
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
	//Constants
	const EnvironmentPaths = EnvPaths( PROCESS_NAME );
	//Variables
	var function_return = [1,null];
	var salt_filepath = null;
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
	//Config
	//Main
	if( process.argv.length > 2 ){
		salt_filepath = process.argv[2];
	}
	function_return = SaltFile_New( salt_filepath );
	_return = function_return;
	if( _return[0] === 0 ){
		process.exitCode = 0;
	} else{
		process.exitCode = _return[0];
		console.error(_return[1]);
	}
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'End of execution block.'});
} else{
	exports.SetLogger = Logger_Set;
	exports.NewSaltFile = SaltFile_New;
	exports.LoadSaltFile = SaltFile_Load;
}

