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
			filepath = Path.join( OperatingSystem.homedir(), '.ssh', 'enc-notes-salt' );
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
		jserrorlog(Util\fmt('%o', _return))
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
			filepath = Path.join( OperatingSystem.homedir(), '.ssh', 'enc-notes-salt' );
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
		jserrorlog(Util\fmt('%o', _return))
	}

	//Return
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('returned code: %d', _return[0])}); //Making sure to NOT log the actual salt data.
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
	var inquirer_questions = [
		{
			type: 'password',
			name: 'password',
			masked: '*'
		}
	];
	var inquirer_answer = null;
	var salt_buffer = Buffer.alloc(32);
	var iv_buffer = Buffer.alloc(1024);
	var scrypt_buffer = null;
	var secret_keyobject = null;
	var cipher = null;
	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: Utility.format('received: ', arguments)});
	//Parametre checks
	
	//Function
	try{
		inquirer_answer = await Inquirer.prompt( inquirer_questions );
		if( inquirer_answer.password != null && typeof(inquirer_answer.password) === 'string' ){
			iv_buffer = Buffer.alloc(32);
			Crypto.randomFillSync(iv_buffer);
			scrypt_buffer = Crypto.scryptSync
	} catch(error){
		jserrorlog(Util\fmt('Inquirer.prompt threw: %s', error))
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
		const Inquirer = require('inquirer');
	//Constants
	const EnvironmentPaths = EnvPaths( PROCESS_NAME );
	const OptionDefinitions = [
		//UI
		{ name: 'help', alias: 'h', type: Boolean, description: 'Writes this help text to stdout.' },
		{ name: 'noop', alias: 'n', type: Boolean, description: 'Show what would be done without actually doing it.' },
		{ name: 'verbose', alias: 'v', type: Boolean, description: 'Verbose output to stderr.' },
		{ name: 'Version', alias: 'V', type: Boolean, description: 'Writes version information to stdout.'},
		//Input
		{ name: 'stdin', alias: 'i', type: Boolean, description: 'Read input from stdin.' },
		{ name: 'input', alias: 'I', type: String, description: 'The path to the file to read input from.'},
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
	var Options = CommandLineArguments( OptionDefinitions );
	//Config
	//Main
	if(Options.help === true){
		const help_sections_array = [
			{
				header: 'encrypt-notes',
				content: 'Encrypts the notes.',
			},
			{
				header: 'Options',
				optionList: OptionDefinitions
			}
		]
		const help_message = CommandLineUsage(help_sections_array);
		console.log(help_message);
	}
	var i

	Logger.log({process: PROCESS_NAME, module: MODULE_NAME, file: FILENAME, function: FUNCTION_NAME, level: 'debug', message: 'End of execution block.'});
} else{
	exports.SetLogger = Logger_Set;
}

