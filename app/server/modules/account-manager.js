'use strict';
import crypto from 'crypto';
import {MongoDB, Server, ObjectID} from 'mongodb';
import moment from 'moment';

const dbPort = 27017;
const dbHost = 'localhost';
const dbName = 'node-login';

/* establish the database connection */

const serverInstance = new Server(dbHost, dbPort, {auto_reconnect: true});
const db = new MongoDB(dbName, serverInstance, {w: 1});

db.open(function (e, d) {
	if (e) {
		return console.log(e);
	}

    console.log('connected to database :: ' + dbName);
});

const accounts = db.collection('accounts');

/* login validation methods */

exports.autoLogin = function(user, pass, callback)
{
	accounts.findOne({user:user}, function(e, o) {
		if (o){
			o.pass == pass ? callback(o) : callback(null);
		}	else{
			callback(null);
		}
	});
}

exports.manualLogin = function(user, pass, callback)
{
	accounts.findOne({user:user}, function(e, o) {
		if (o == null){
			callback('user-not-found');
		}	else{
			validatePassword(pass, o.pass, function(err, res) {
				if (res){
					callback(null, o);
				}	else{
					callback('invalid-password');
				}
			});
		}
	});
}

/* record insertion, update & deletion methods */

exports.addNewAccount = function(newData, callback)
{
	accounts.findOne({user:newData.user}, function(e, o) {
		if (o){
			callback('username-taken');
		}	else{
			accounts.findOne({email:newData.email}, function(e, o) {
				if (o){
					callback('email-taken');
				}	else{
					saltAndHash(newData.pass, function(hash){
						newData.pass = hash;
					// append date stamp when record was created //
						newData.date = moment().format('MMMM Do YYYY, h:mm:ss a');
						accounts.insert(newData, {safe: true}, callback);
					});
				}
			});
		}
	});
}

exports.updateAccount = function(newData, callback)
{
	accounts.findOne({user:newData.user}, function(e, o){
		o.name 		= newData.name;
		o.email 	= newData.email;
		o.country 	= newData.country;
		if (newData.pass == ''){
			accounts.save(o, {safe: true}, function(err) {
				if (err) callback(err);
				else callback(null, o);
			});
		}	else{
			saltAndHash(newData.pass, function(hash){
				o.pass = hash;
				accounts.save(o, {safe: true}, function(err) {
					if (err) callback(err);
					else callback(null, o);
				});
			});
		}
	});
}

exports.updatePassword = function(email, newPass, callback)
{
	accounts.findOne({email:email}, function(e, o){
		if (e){
			callback(e, null);
		}	else{
			saltAndHash(newPass, function(hash){
		        o.pass = hash;
		        accounts.save(o, {safe: true}, callback);
			});
		}
	});
}

/* account lookup methods */

exports.deleteAccount = function(id, callback)
{
	accounts.remove({_id: getObjectId(id)}, callback);
}

exports.getAccountByEmail = function(email, callback)
{
	accounts.findOne({email:email}, function(e, o){ callback(o); });
}

exports.validateResetLink = function(email, passHash, callback)
{
	accounts.find({ $and: [{email:email, pass:passHash}] }, function(e, o){
		callback(o ? 'ok' : null);
	});
}

export function getAllRecords(callback)
{
    function toArrayCb(e, res) {
        if (e) {
            callback(e);
            return;
        }

        callback(null, res);
    }

	accounts.find().toArray(toArrayCb);
}

export function delAllRecords(callback)
{
	accounts.remove({}, callback); // reset accounts collection for testing //
}

/***
 * Private encryption & validation methods.
 * @returns {string} Salt string.
 */
function generateSalt()
{
	const chars = '0123456789abcdefghijklmnopqurstuvwxyzABCDEFGHIJKLMNOPQURSTUVWXYZ';
    let salt = '';
	for (let i = 0; i < 10; i++) {
		const p = Math.floor(Math.random() * chars.length);
		salt += chars[p];
	}
	return salt;
}

function md5(str) {
	return crypto.createHash('md5').update(str).digest('hex');
}

function saltAndHash(pass, callback)
{
	const salt = generateSalt();

	callback(salt + md5(pass + salt));
}

function validatePassword(plainPass, hashedPass, callback)
{
	const salt = hashedPass.substr(0, 10);
    const validHash = salt + md5(plainPass + salt);

	callback(null, hashedPass === validHash);
}

/* auxiliary methods */

function getObjectId(id)
{
	return new ObjectID(id);
}

function findById(id, callback)
{
	accounts.findOne({_id: getObjectId(id)}, callback);
}

function findByMultipleFields(a, callback)
{
    // this takes an array of name/val pairs to search against {fieldName : 'value'} //
	accounts.find( { $or : a } ).toArray(callback);
}
