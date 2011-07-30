/*
 * Copyright (c) 2011, 1PS.RU <admin@1ps.ru>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 
 *     Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *     
 *     Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <sstream>
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <time.h>
#include <locale.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <glib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>

namespace UploadS3 {

typedef struct _Upload {
	std::string key;
	std::string id;
	time_t initiated;
} Upload;

typedef struct _Part {
	int num;
	std::string etag;
	size_t size;
} Part;

typedef struct _Contents {
	std::string key;
	time_t last_modified;
	std::string etag;
	size_t size;
} Contents;

const size_t UPLOAD_PART_SIZE = 5242880; // 1024; //(5 * 1024 * 1024);

class Job {
public:
	Job(std::string aws_key, std::string aws_secret, std::string bucket);
	Job(std::string config_file, bool verbose = false, bool progress = false);
	~Job();
	bool init(std::string aws_key, std::string aws_secret, std::string bucket);
	bool upload(const std::string fname, const std::string prefix = "", bool cont = false, bool keep = false);
	bool deleteOldUploads(int days = 5);
	bool test(const std::string fname, const std::string prefix, bool& exists);

	bool listMultipartUploads(std::vector<Upload>& upload_list);
	bool abortMultipartUpload(std::string key, std::string id);
	bool initiateMultipartUpload(std::string key, std::string &upload_id);
	bool completeMultipartUpload(std::string key, std::string id, std::vector<Part> part_list);
	bool uploadPart(std::string key, std::string id, int num, std::string data, Part &part);
	bool listParts(std::string key, std::string upload_id, std::vector<Part> &part_list);
	bool listObjects(std::vector< Contents >& contents_list, std::string prefix = "");
protected:
	bool verbose;
	bool progress;
	size_t p_size;
	size_t p_cur;
	size_t p_start;
	size_t p_part_pos;
	struct timeval p_begin;
	CURL *curl;
	char *curl_error;
	std::string request_data;
	off_t request_data_pos;
	std::string responce;
	long responce_code;
	std::map<std::string, std::string> responce_headers;
	xmlDocPtr doc;
private:
	std::string aws_key;
	std::string aws_secret;
	std::string bucket;
	
	static size_t curl_write_callback(void *ptr, size_t size, size_t nmemb, void *userdata);
	size_t curl_write(void *ptr, size_t size, size_t nmemb);
	static size_t curl_read_callback(void *ptr, size_t size, size_t nmemb, void *userdata);
	size_t curl_read(void *ptr, size_t size, size_t nmemb);
	static size_t curl_header_callback(void *ptr, size_t size, size_t nmemb, void *userdata);
	size_t curl_header(void *ptr, size_t size, size_t nmemb);
	bool request(std::string method, std::string subres, std::string query, std::string data = "");
	void drawProgress();
};

Job::Job(std::string aws_key, std::string aws_secret, std::string bucket)
{
	this->init(aws_key, aws_secret, bucket);
}

Job::Job(std::string config_file, bool verbose, bool progress)
{
    GKeyFile* key_file;
    GError* error = NULL;
    gchar* str;
	std::string aws_key;
	std::string aws_secret;
	std::string bucket;
	
	this->verbose = verbose;
	this->progress = progress;

    key_file = g_key_file_new();
    
    if (!g_key_file_load_from_file(key_file, config_file.c_str(), G_KEY_FILE_NONE, &error)) {
        g_print("config load failed: %s\n", error->message);
        return;
    }
    
    str = g_key_file_get_string(key_file, "upload_s3", "aws_key", &error);
    if (!str) {
        g_print("aws_key: %s\n", error->message);
        return;
    } else {
        aws_key = str;
    }
    
    str = g_key_file_get_string(key_file, "upload_s3", "aws_secret", &error);
    if (!str) {
        g_print("aws_secret: %s\n", error->message);
        return;
    } else {
        aws_secret = str;
    }

    str = g_key_file_get_string(key_file, "upload_s3", "bucket", &error);
    if (!str) {
        g_print("bucket: %s\n", error->message);
        return;
    } else {
        bucket = str;
    }

	this->init(aws_key, aws_secret, bucket);
}

bool Job::init(std::string aws_key, std::string aws_secret, std::string bucket)
{
	this->aws_key = aws_key;
	this->aws_secret = aws_secret;
	this->bucket = bucket;
	
	this->curl = curl_easy_init();
	this->curl_error = (char *) malloc(CURL_ERROR_SIZE + 1);
	this->curl_error[0] = '\0';
	curl_easy_setopt(this->curl, CURLOPT_ERRORBUFFER, this->curl_error);
	
	this->responce_code = 0;
	this->doc = NULL;
}

Job::~Job()
{
	if (this->curl)
		curl_easy_cleanup(this->curl);
	if (this->curl_error)
		free(this->curl_error);
	if (this->doc)
		xmlFreeDoc(this->doc);
}

bool Job::upload(const std::string fname, const std::string prefix, bool cont, bool keep)
{
	char *baset, *base;
	std::string key, upload_id, data;
	int fd;
	struct stat stat;
	size_t fsize;
	int partno = 1;
	off64_t offset = 0;
	std::vector<Part> parts;
	char buf[UPLOAD_PART_SIZE];
	size_t buf_len;
	Part part;
	std::vector<Upload> upload_list;
	struct timeval begin;
	struct timeval end;
	long usec_begin, usec_end;
	size_t send = 0;
	double speed;
	std::vector<Contents> contents_list;
	
	if (this->progress) {
		this->p_size = this->p_cur = this->p_start = this->p_part_pos = 0;
		memset(&this->p_start, '\0', sizeof(this->p_start));
	}
	
	baset = (char *) malloc(fname.size() + 1);
	fname.copy(baset, fname.size());
	baset[fname.size()] = '\0';
	base = basename(baset);
	key = prefix;
	key += base;
	
	fd = open(fname.c_str(), O_RDONLY | O_LARGEFILE);
	if (fd == -1) {
		perror("Can't open file");
		return false;
	}
	if (flock(fd, LOCK_SH)) {
		perror("Can't lock file");
		close(fd);
		return false;
	}
	if (fstat(fd, &stat)) {
		perror("Can't stat file");
		close(fd);
		return false;
	}
	fsize = stat.st_size;
	this->p_size = fsize;

	if (keep) {
		if (!this->listObjects(contents_list, key)) {
			return false;
		}
		for (std::vector<Contents>::iterator ii = contents_list.begin(); ii != contents_list.end(); ++ii) {
			if (key == (*ii).key) {
				if (this->verbose) {
					std::cout << "File " << key << " with size " << (*ii).size << " already exists, last modified at " << ctime(&(*ii).last_modified);
				}
				flock(fd, LOCK_UN);
				close(fd);
				return true;
			}
		}
	}
	
	if (cont) {
		if (!this->listMultipartUploads(upload_list)) {
			return false;
		}
		for (std::vector<Upload>::iterator ii = upload_list.begin(); ii != upload_list.end(); ++ii) {
			if (key == (*ii).key) {
				upload_id = (*ii).id;
				break;
			}
		}
		if (upload_id != "") {
			if (this->verbose) {
				std::cout << "Continue upload id: " << upload_id << std::endl;
			}
			if (!this->listParts(key, upload_id, parts)) {
				return false;
			}
			for (std::vector<Part>::iterator ii = parts.begin(); ii != parts.end(); ++ii) {
				// std::cout << "found part " << (*ii).num << " " << (*ii).size << std::endl;
				partno = (*ii).num + 1;
				offset += (*ii).size;
			}
			this->p_start = offset;
			this->p_cur = offset;
			if (this->verbose) {
				std::cout << "Continue from part " << partno << ", " << offset << " bytes, " << (fsize - offset) << " bytes left" << std::endl;
			}
		}
	}

	if (upload_id == "") {
		if (!this->initiateMultipartUpload(key, upload_id)) {
			return false;
		}
		if (this->verbose) {
			std::cout << "New upload id: " << upload_id << std::endl;
		}
	}
	
	if ((fsize - offset) > 0) {
		gettimeofday(&begin, NULL);
		this->p_begin = begin;
		for (; partno <= (fsize / UPLOAD_PART_SIZE) + 1; ++partno) {
			if (lseek64(fd, offset, SEEK_SET) == -1) {
				perror("Can't seek file");
				return false;
			}
			buf_len = read(fd, buf, UPLOAD_PART_SIZE);
			data.assign(buf, buf_len);
			if (!this->uploadPart(key, upload_id, partno, data, part)) {
				return false;
			}
			// std::cout << partno << " done" << std::endl;
			parts.push_back(part);
			offset += UPLOAD_PART_SIZE;
			send += buf_len;
		}
		gettimeofday(&end, NULL);
	}
	
	if (!this->completeMultipartUpload(key, upload_id, parts)) {
		return false;
	}
	
	if (this->verbose && send > 0) {
		usec_begin = begin.tv_usec + begin.tv_sec * 1000000;
		usec_end = end.tv_usec + end.tv_sec * 1000000;
		speed = (((send + 0.0) / (usec_end - usec_begin)) / 1024) * 1000000;
		std::cout << std::setprecision(2) << std::fixed << "Uploaded " << send << " bytes in " << ((usec_end - usec_begin) / 1000000.0) << " seconds mean " << speed << " Kbytes/sec" << std::endl;
	}
	
	flock(fd, LOCK_UN);
	close(fd);
	
	return true;
}

bool Job::deleteOldUploads(int days)
{
	std::vector<Upload> uploads;
	time_t now = time(NULL);
	
	if (!this->listMultipartUploads(uploads)) {
		return false;
	}
	for (std::vector<Upload>::iterator ii = uploads.begin(); ii != uploads.end() ; ++ii) {
		// std::cout << (*ii).id << " " << (*ii).key << " " << (*ii).initiated << std::endl;
		if ((*ii).initiated && (*ii).initiated < now - days * 3600 * 24) { // X days ago
			if (!this->abortMultipartUpload((*ii).key, (*ii).id)) {
				return false;
			}
			if (this->verbose) {
				std::cout << "Deleted stalled upload for " << (*ii).key << " initiated at " << ctime(&(*ii).initiated);
			}
		}
	}
	return true;
}

bool Job::test(const std::string fname, const std::string prefix, bool& exists)
{
	char *baset, *base;
	std::string key;
	std::vector<Contents> contents_list;
	
	baset = (char *) malloc(fname.size() + 1);
	fname.copy(baset, fname.size());
	baset[fname.size()] = '\0';
	base = basename(baset);
	key = prefix;
	key += base;
	
	exists = false;
	
	if (!this->listObjects(contents_list, key)) {
		return false;
	}
	for (std::vector<Contents>::iterator ii = contents_list.begin(); ii != contents_list.end(); ++ii) {
		if (key == (*ii).key) {
			if (this->verbose) {
				std::cout << key << "\t" << (*ii).size << "\t" << ctime(&(*ii).last_modified);
			}
			exists = true;
			return true;
		}
	}
	
	return true;
}

bool Job::listMultipartUploads(std::vector< Upload > &upload_list)
{
	xmlXPathContextPtr xpathCtx; 
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	int nodes_size;
	xmlNodePtr cur, upload_cur;
	std::string upload_key;
	std::string upload_id;
	struct tm tm;
	time_t upload_initiated;
	xmlChar *content;
	Upload upload;
	
	if (!this->request("GET", "/?uploads", "/?uploads")) {
		return false;
	}
	if (this->responce_code != 200) {
		std::cerr << "Error while trying to get list of multipart uploads: " << this->responce << std::endl;
		return false;
	}
	if (!this->doc) {
		std::cerr << "Error: responce is unavailable" << std::endl;
		return false;
	}
	
	xpathCtx = xmlXPathNewContext(this->doc);
	if (xpathCtx == NULL) {
		std::cerr << "Error: unable to create new XPath context" << std::endl;
		return false;
	}
	xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "aws", (const xmlChar *) "http://s3.amazonaws.com/doc/2006-03-01/");
	xpathObj = xmlXPathEvalExpression((const xmlChar *) "/aws:ListMultipartUploadsResult/aws:Upload", xpathCtx);
	if (xpathObj == NULL) {
		std::cerr << "Error: unable to evaluate xpath expression" << std::endl;
		xmlXPathFreeContext(xpathCtx);
		return false;
	}
	nodes = xpathObj->nodesetval;
	nodes_size = (nodes) ? nodes->nodeNr : 0;
	// std::cout << "nodes_size: " << nodes_size << std::endl;
	for (int i = 0; i < nodes_size; ++i) {
		cur = nodes->nodeTab[i];
		if (cur->type == XML_ELEMENT_NODE) {
			upload_cur = cur->children;
			upload_key = "";
			upload_id = "";
			upload_initiated = 0;
			while (upload_cur != NULL) {
				content = xmlNodeGetContent(upload_cur);
				if (content) {
					if (strcmp((char *) upload_cur->name, "Key") == 0) {
						upload_key = (char *) content;
					} else if (strcmp((char *) upload_cur->name, "UploadId") == 0) {
						upload_id = (char *) content;
					} else if (strcmp((char *) upload_cur->name, "Initiated") == 0) {
						if (!strptime((char *) content, "%FT%T.000Z", &tm)) {
							perror("Can't parse date");
							return false;
						}
						upload_initiated = mktime(&tm);
					}
				}
				upload_cur = upload_cur->next;
			}
			// std::cout << upload_key << " " << upload_id << " " << upload_initiated << std::endl;
			upload.key = upload_key;
			upload.id = upload_id;
			upload.initiated = upload_initiated;
			upload_list.push_back(upload);
		}
	}
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	
	return true;
}

bool Job::abortMultipartUpload(std::string key, std::string id)
{
	std::stringstream cmd;
	
	cmd << "/" << key << "?uploadId=" << id;
	if (!this->request("DELETE", cmd.str(), cmd.str())) {
		return false;
	}
	return true;
}

bool Job::completeMultipartUpload(std::string key, std::string id, std::vector< Part > part_list)
{
	std::stringstream cmd, data;
	xmlXPathContextPtr xpathCtx; 
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	int nodes_size;
	xmlNodePtr cur;
	std::string etag, code, message;
	bool error_found = false;
	
	cmd << "/" << key << "?uploadId=" << id;
	data << "<CompleteMultipartUpload>" << std::endl;
	for (std::vector<Part>::iterator ii = part_list.begin(); ii != part_list.end(); ++ii) {
		data << "<Part>" << std::endl;
		data << "<PartNumber>" << (*ii).num << "</PartNumber>" << std::endl;
		data << "<ETag>" << (*ii).etag << "</ETag>" << std::endl;
		data << "</Part>" << std::endl;
	}
	data << "</CompleteMultipartUpload>" << std::endl;
	// std::cout << data.str() << std::endl;
	if (!this->request("POST", cmd.str(), cmd.str(), data.str())) {
		return false;
	}
	if (this->responce_code != 200) {
		std::cerr << "Can't complete multipart upload: " << this->responce << std::endl;
		return false;
	}
	
	xpathCtx = xmlXPathNewContext(this->doc);
	if (xpathCtx == NULL) {
		std::cerr << "Error: unable to create new XPath context" << std::endl;
		return false;
	}
	xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "aws", (const xmlChar *) "http://s3.amazonaws.com/doc/2006-03-01/");
	xpathObj = xmlXPathEvalExpression((const xmlChar *) "/Error", xpathCtx);
	if (xpathObj == NULL) {
		std::cerr << "Error: unable to evaluate xpath expression" << std::endl;
		xmlXPathFreeContext(xpathCtx);
		return false;
	}
	nodes = xpathObj->nodesetval;
	nodes_size = (nodes) ? nodes->nodeNr : 0;
	// std::cout << "nodes_size: " << nodes_size << std::endl;
	for (int i = 0; i < nodes_size; ++i) {
		error_found = true;
		cur = nodes->nodeTab[i]->children;
		while (cur != NULL) {
			if (strcmp((char *) cur->name, "Code") == 0) {
				code = (char *) xmlNodeGetContent(cur);
			} else if (strcmp((char *) cur->name, "Message") == 0) {
				message = (char *) xmlNodeGetContent(cur);
			}
			cur = cur->next;
		}
	}
	xmlXPathFreeObject(xpathObj);
	if (error_found) {
		xmlXPathFreeContext(xpathCtx);
		std::cerr << "Error in complete multipart upload: " << code << " " << message << std::endl;
		return false;
	}
	xpathObj = xmlXPathEvalExpression((const xmlChar *) "/aws:CompleteMultipartUpload", xpathCtx);
	if (xpathObj == NULL) {
		std::cerr << "Error: unable to evaluate xpath expression" << std::endl;
		xmlXPathFreeContext(xpathCtx);
		return false;
	}
	nodes = xpathObj->nodesetval;
	nodes_size = (nodes) ? nodes->nodeNr : 0;
	// std::cout << "nodes_size: " << nodes_size << std::endl;
	for (int i = 0; i < nodes_size; ++i) {
		cur = nodes->nodeTab[i]->children;
		while (cur != NULL) {
			if (strcmp((char *) cur->name, "Key") == 0) {
				etag = (char *) xmlNodeGetContent(cur);
			}
			cur = cur->next;
		}
	}
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	// std::cout << this->responce_code << " " << this->responce << std::endl;

	return true;
}

bool Job::initiateMultipartUpload(std::string key, std::string &upload_id)
{
	std::stringstream cmd;
	xmlXPathContextPtr xpathCtx; 
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	int nodes_size;
	xmlNodePtr cur;
	xmlChar *content;
	
	cmd << "/" << key << "?uploads";
	if (!this->request("POST", cmd.str(), cmd.str())) {
		return false;
	}
	if (!this->doc) {
		std::cerr << "Error: responce is unavailable" << std::endl;
		return false;
	}
	
	xpathCtx = xmlXPathNewContext(this->doc);
	if (xpathCtx == NULL) {
		std::cerr << "Error: unable to create new XPath context" << std::endl;
		return false;
	}
	xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "aws", (const xmlChar *) "http://s3.amazonaws.com/doc/2006-03-01/");
	xpathObj = xmlXPathEvalExpression((const xmlChar *) "/aws:InitiateMultipartUploadResult/aws:UploadId", xpathCtx);
	if (xpathObj == NULL) {
		std::cerr << "Error: unable to evaluate xpath expression" << std::endl;
		xmlXPathFreeContext(xpathCtx);
		return false;
	}
	nodes = xpathObj->nodesetval;
	nodes_size = (nodes) ? nodes->nodeNr : 0;
	// std::cout << "nodes_size: " << nodes_size << std::endl;
	for (int i = 0; i < nodes_size; ++i) {
		cur = nodes->nodeTab[i];
		if (cur->type == XML_ELEMENT_NODE && strcmp((char *) cur->name, "UploadId") == 0) {
			content = xmlNodeGetContent(cur);
			upload_id = (char *) content;
			// std::cout << "new upload id: " << upload_id << std::endl;
		}
	}
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	
	return true;
}

bool Job::uploadPart(std::string key, std::string id, int num, std::string data, Part& part)
{
	std::stringstream cmd;
	int tries = 0;
	
	cmd << "/" << key << "?partNumber=" << num << "&uploadId=" << id;
	while (tries < 1001) {
		if (!this->request("PUT", cmd.str(), cmd.str(), data)) { // trying until success
			std::cerr << "Error occur while uploading part: " << this->responce << std::endl;
			return false; // some error occur
		}
		if (this->responce_code == 200) {
			break; // ok
		}
		tries += 1;
		if (this->progress) {
			this->p_part_pos = 0;
		}
	}
	if (tries == 1001) {
		std::cerr << "Attempt limit reached in upload part; bailing out" << std::endl;
		return false;
	}
	if (this->progress) {
		this->p_part_pos = 0;
		this->p_cur += data.size();
	}
	part.num = num;
	part.etag = this->responce_headers["ETag"];
	
	return true;
}

bool Job::listParts(std::string key, std::string upload_id, std::vector< Part >& part_list)
{
	std::stringstream cmd, subres;
	xmlXPathContextPtr xpathCtx; 
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	int nodes_size;
	xmlNodePtr cur, cur_part;
	bool need_continue = false;
	std::string part_number_marker;
	Part part;
	std::istringstream iss;
	
	while (true) {
		need_continue = false;
		subres.str("");
		subres << "/" << key << "?uploadId=" << upload_id;
		cmd.str("");
		cmd << subres.str();
		if (part_number_marker != "") {
			cmd << "&part-number-marker=" << part_number_marker;
		}
		if (!this->request("GET", subres.str(), cmd.str())) {
			return false;
		}
		if (this->responce_code != 200) {
			std::cerr << "Error while trying to get list parts of multipart uploads: " << this->responce << std::endl;
			return false;
		}
		if (!this->doc) {
			std::cerr << "Error: responce is unavailable" << std::endl;
			return false;
		}
		
		xpathCtx = xmlXPathNewContext(this->doc);
		if (xpathCtx == NULL) {
			std::cerr << "Error: unable to create new XPath context" << std::endl;
			return false;
		}
		xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "aws", (const xmlChar *) "http://s3.amazonaws.com/doc/2006-03-01/");
		xpathObj = xmlXPathEvalExpression((const xmlChar *) "/aws:ListPartsResult", xpathCtx);
		if (xpathObj == NULL) {
			std::cerr << "Error: unable to evaluate xpath expression" << std::endl;
			xmlXPathFreeContext(xpathCtx);
			return false;
		}
		nodes = xpathObj->nodesetval;
		nodes_size = (nodes) ? nodes->nodeNr : 0;
		// std::cout << "nodes_size: " << nodes_size << std::endl;
		for (int i = 0; i < nodes_size; ++i) {
			cur = nodes->nodeTab[i]->children;
			while (cur != NULL) {
				if (strcmp((char *) cur->name, "IsTruncated") == 0 && strcmp((char *) xmlNodeGetContent(cur), "true") == 0) {
					need_continue = true;
				} else if (strcmp((char *) cur->name, "NextPartNumberMarker") == 0) {
					part_number_marker = (char *) xmlNodeGetContent(cur);
				} else if (strcmp((char *) cur->name, "Part") == 0) {
					cur_part = cur->children;
					part.etag = "";
					part.num = 0;
					part.size = 0;
					while (cur_part != NULL) {
						if (strcmp((char *) cur_part->name, "PartNumber") == 0) {
							iss.clear();
							iss.str((char *) xmlNodeGetContent(cur_part));
							iss >> part.num;
							// std::cout << "num: " << (char *) xmlNodeGetContent(cur_part) << " " << part.num << std::endl;
						} else if (strcmp((char *) cur_part->name, "ETag") == 0) {
							part.etag = (char *) xmlNodeGetContent(cur_part);
						} else if (strcmp((char *) cur_part->name, "Size") == 0) {
							iss.clear();
							iss.str((char *) xmlNodeGetContent(cur_part));
							iss >> part.size;
							// std::cout << "size: " << (char *) xmlNodeGetContent(cur_part) << " " << part.size << std::endl;
						}
						cur_part = cur_part->next;
					}
					// std::cout << "there with " << part.num << " " << part.etag << " " << part.size << std::endl;
					if (part.num > 0 && part.etag != "" && part.size > 0) {
						part_list.push_back(part);
					}
				}
				cur = cur->next;
			}
		}
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		
		if (!need_continue) {
			break;
		}
	}

	return true;
}

bool Job::listObjects(std::vector< Contents >& contents_list, std::string prefix)
{
	std::stringstream cmd, subres;
	xmlXPathContextPtr xpathCtx; 
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	int nodes_size;
	xmlNodePtr cur, cur_contents;
	bool need_continue = false;
	std::string marker;
	Contents contents;
	std::istringstream iss;
	struct tm tm;
	char* enc;
	
	while (true) {
		// std::cout << "there with " << marker << std::endl;
		need_continue = false;
		subres.str("");
		subres << "/";
		cmd.str("");
		cmd << subres.str();
		if (prefix != "") {
			enc = curl_easy_escape(this->curl, prefix.c_str(), prefix.size());
			cmd << "?prefix=" << enc;
			curl_free(enc);
		}
		if (marker != "") {
			enc = curl_easy_escape(this->curl, marker.c_str(), marker.size());
			cmd << (prefix == "" ? "?" : "&") << "marker=" << enc;
			curl_free(enc);
		}
		if (!this->request("GET", subres.str(), cmd.str())) {
			return false;
		}
		if (this->responce_code != 200) {
			std::cerr << "Error while trying to get list of objects: " << this->responce << std::endl;
			return false;
		}
		if (!this->doc) {
			std::cerr << "Error: responce is unavailable" << std::endl;
			return false;
		}
		
		xpathCtx = xmlXPathNewContext(this->doc);
		if (xpathCtx == NULL) {
			std::cerr << "Error: unable to create new XPath context" << std::endl;
			return false;
		}
		xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "aws", (const xmlChar *) "http://s3.amazonaws.com/doc/2006-03-01/");
		xpathObj = xmlXPathEvalExpression((const xmlChar *) "/aws:ListBucketResult", xpathCtx);
		if (xpathObj == NULL) {
			std::cerr << "Error: unable to evaluate xpath expression" << std::endl;
			xmlXPathFreeContext(xpathCtx);
			return false;
		}
		nodes = xpathObj->nodesetval;
		nodes_size = (nodes) ? nodes->nodeNr : 0;
		// std::cout << "nodes_size: " << nodes_size << std::endl;
		for (int i = 0; i < nodes_size; ++i) {
			cur = nodes->nodeTab[i]->children;
			while (cur != NULL) {
				if (strcmp((char *) cur->name, "IsTruncated") == 0 && strcmp((char *) xmlNodeGetContent(cur), "true") == 0) {
					need_continue = true;
				} else if (strcmp((char *) cur->name, "Marker") == 0) {
					marker = (char *) xmlNodeGetContent(cur);
				} else if (strcmp((char *) cur->name, "Contents") == 0) {
					cur_contents = cur->children;
					contents.etag = "";
					contents.key = "";
					contents.last_modified = 0;
					contents.size = 0;
					while (cur_contents != NULL) {
						if (strcmp((char *) cur_contents->name, "ETag") == 0) {
							contents.etag = (char *) xmlNodeGetContent(cur_contents);
						} else if (strcmp((char *) cur_contents->name, "Key") == 0) {
							contents.key = (char *) xmlNodeGetContent(cur_contents);
						} else if (strcmp((char *) cur_contents->name, "LastModified") == 0) {
							if (!strptime((char *) xmlNodeGetContent(cur_contents), "%FT%T.000Z", &tm)) {
								perror("Can't parse date");
								return false;
							}
							contents.last_modified = mktime(&tm);
						} else if (strcmp((char *) cur_contents->name, "Size") == 0) {
							iss.clear();
							iss.str((char *) xmlNodeGetContent(cur_contents));
							iss >> contents.size;
						}
						cur_contents = cur_contents->next;
					}
					contents_list.push_back(contents);
				}
				cur = cur->next;
			}
		}
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		
		if (!need_continue) {
			break;
		}
	}

	return true;
}

size_t Job::curl_write_callback(void* ptr, size_t size, size_t nmemb, void* userdata)
{
	return ((Job *) userdata)->curl_write(ptr, size, nmemb);
}

size_t Job::curl_write(void* ptr, size_t size, size_t nmemb)
{
	this->responce.append((char *) ptr, size * nmemb);
	return size * nmemb;
}

size_t Job::curl_read_callback(void* ptr, size_t size, size_t nmemb, void* userdata)
{
	return ((Job *) userdata)->curl_read(ptr, size, nmemb);
}

size_t Job::curl_read(void* ptr, size_t size, size_t nmemb)
{
	size_t out = ((size * nmemb) < (this->request_data.size() - this->request_data_pos)) ? 
		(size * nmemb) : 
		(this->request_data.size() - this->request_data_pos);
	if (out > 0) {
		this->request_data.copy((char *) ptr, out, this->request_data_pos);
	}
	// std::cout << "read " << out << " bytes" << std::endl;
	this->request_data_pos += out;
	
	if (this->progress) {
		this->p_part_pos += out;
		this->drawProgress();
	}
	
	return out;
}

size_t Job::curl_header_callback(void* ptr, size_t size, size_t nmemb, void* userdata)
{
	return ((Job *) userdata)->curl_header(ptr, size, nmemb);
}

size_t Job::curl_header(void* ptr, size_t size, size_t nmemb)
{
	std::string header, name, value;
	size_t pos1, pos2, pos3;
	
	header.assign((char *) ptr, size * nmemb);
	// std::cout << "header in: " << header;
	pos1 = header.find_first_of(": \t");
	if (pos1 != std::string::npos) {
		name = header.substr(0, pos1);
		pos2 = header.find_first_not_of(": \t", pos1);
		pos3 = header.find_last_not_of(" \t\r\n");
		if (pos2 != std::string::npos && pos3 != std::string::npos) {
			value = header.substr(pos2, pos3 - pos2 + 1);
			// std::cout << pos2 << ", " << pos3 << ", " << header.size() << " parsed " << name << ": '" << value << "'" << std::endl;
			this->responce_headers[name] = value;
		}
	}
	
	return size * nmemb;
}

int curl_debug_callback(CURL *curl, curl_infotype type, char *msg, size_t msg_len, void *udata) {
	std::string str;
	str.assign(msg, msg_len);
	if (type == CURLINFO_HEADER_OUT) {
		std::cout << "header out: " << str << std::endl;
	}
	return 0;
}

bool Job::request(std::string method, std::string subres, std::string query, std::string data)
{
	int rc, i;
	struct curl_slist *slist = NULL;
	time_t stamp;
	char stamp_str[1024];
	std::string date_header;
	std::string auth_header;
	std::stringstream length_header;
	std::string string_to_sign;
	char sig[EVP_MAX_MD_SIZE];
	std::string sig_b64;
	unsigned int sig_len;
	BIO *bio, *b64;
	BUF_MEM *bptr;
	std::stringstream buf;
	unsigned char md5_sum[MD5_DIGEST_LENGTH];
	std::string md5_b64;
	std::string md5_header;
	
	buf.str("");
	buf << "http://" << this->bucket << ".s3.amazonaws.com" << query;
	// curl_easy_setopt(this->curl, CURLOPT_VERBOSE, 1);
	// curl_easy_setopt(this->curl, CURLOPT_DEBUGFUNCTION, curl_debug_callback);
	curl_easy_setopt(this->curl, CURLOPT_URL, buf.str().c_str());
	curl_easy_setopt(this->curl, CURLOPT_CUSTOMREQUEST, method.c_str());
	curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, NULL);
	if (method == "PUT") {
		curl_easy_setopt(this->curl, CURLOPT_UPLOAD, 1);
	}
	stamp = time(NULL);
	setlocale(LC_TIME, "C");
	strftime(stamp_str, sizeof(stamp_str), "%a, %e %b %Y %T %z", gmtime(&stamp));
	date_header = "Date: ";
	date_header += stamp_str;
	if (data.size() > 0) {
		MD5((unsigned char *) data.data(), data.size(), md5_sum);
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new(BIO_s_mem());
		b64 = BIO_push(b64, bio);
		BIO_write(b64, md5_sum, MD5_DIGEST_LENGTH);
		BIO_flush(b64);
		BIO_get_mem_ptr(b64, &bptr);
		md5_b64.assign(bptr->data, bptr->length - 1);
		BIO_free_all(b64);
		md5_header = "Content-MD5: ";
		md5_header += md5_b64;
	}
	string_to_sign = method + "\n";
	string_to_sign += md5_b64;
	string_to_sign += "\n";
	// if (method == "POST" && data.size() == 0) {
		// string_to_sign += "application/x-www-form-urlencoded";
	// }
	string_to_sign += "\n";
	string_to_sign += stamp_str;
	string_to_sign += "\n";
	string_to_sign += "/";
	string_to_sign += this->bucket;
	string_to_sign += subres;
	// std::cout << "'" << string_to_sign << "'" << std::endl;
	HMAC(EVP_sha1(), this->aws_secret.c_str(), this->aws_secret.size(), (unsigned char *) string_to_sign.c_str(), string_to_sign.size(), (unsigned char *) sig, &sig_len);
	// std::cout << "sig_len: " << sig_len << std::endl;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bio);
	BIO_write(b64, sig, sig_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);
	sig_b64.assign(bptr->data, bptr->length - 1);
	BIO_free_all(b64);
	// std::cout << sig_b64 << std::endl;
	auth_header = "Authorization: AWS ";
	auth_header += aws_key;
	auth_header += ":";
	auth_header += sig_b64;
	length_header << "Content-Length: " << data.size();
	// std::cout << length_header.str() << std::endl;
	slist = curl_slist_append(slist, length_header.str().c_str());
	slist = curl_slist_append(slist, date_header.c_str());
	slist = curl_slist_append(slist, auth_header.c_str());
	if (md5_header != "") {
		slist = curl_slist_append(slist, md5_header.c_str());
	}
	slist = curl_slist_append(slist, "Transfer-Encoding:");
	slist = curl_slist_append(slist, "Accept:");
	slist = curl_slist_append(slist, "Content-Type:");
	curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, slist);
	this->responce = "";
	this->responce_code = 0;
	this->responce_headers.clear();
	this->request_data = data;
	this->request_data_pos = 0;
	curl_easy_setopt(this->curl, CURLOPT_READFUNCTION, Job::curl_read_callback);
	curl_easy_setopt(this->curl, CURLOPT_READDATA, this);
	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, Job::curl_write_callback);
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, this);
	curl_easy_setopt(this->curl, CURLOPT_HEADERFUNCTION, Job::curl_header_callback);
	curl_easy_setopt(this->curl, CURLOPT_WRITEHEADER, this);
	rc = curl_easy_perform(this->curl);
	curl_slist_free_all(slist);
	if (rc != 0) {
		std::cerr << "Curl error (" << rc << "): " << this->curl_error << std::endl;
		return false;
	}
	// std::cout << this->responce << std::endl;
	if (this->doc) {
		xmlFreeDoc(this->doc);
		this->doc = NULL;
	}
	curl_easy_getinfo(this->curl, CURLINFO_RESPONSE_CODE, &this->responce_code);
	// std::cout << "Code: " << this->responce_code << std::endl;
	// std::cout << this->responce << std::endl;
	if (this->responce.size() > 0) {
		this->doc = xmlReadMemory(this->responce.c_str(), this->responce.size(), "noname.xml", NULL, 0);
		if (this->doc == NULL) {
			std::cerr << "Failed to parse document" << std::endl;
			return false;
		}
	}
	return true;
}

void Job::drawProgress()
{
	static std::string indicator = "|";
	int percent = (this->p_cur + this->p_part_pos) * 100 / this->p_size;
	struct timeval now;
	static struct timeval prev = {0, 0};
	double speed;
	std::stringstream buf, buf2;
	time_t elapsed;
	
	gettimeofday(&now, NULL);
	if (prev.tv_sec != 0 && ((now.tv_sec + now.tv_usec / 1000000.0) - (prev.tv_sec + prev.tv_usec / 1000000.0)) < 0.5) {
		return;
	}
	prev = now;
	speed = ((this->p_cur - this->p_start + this->p_part_pos) + 0.0) / 
		((now.tv_sec + now.tv_usec / 1000000) - (this->p_begin.tv_sec + this->p_begin.tv_usec / 1000000));
	buf << std::fixed << std::setprecision(2) << std::setw(8);
	if (speed > 1024 * 1024 * 1024) {
		buf << (speed / (1024 * 1024 * 1024)) << " GB/s";
	} else if (speed > 1024 * 1024) {
		buf << (speed / (1024 * 1024)) << " MB/s";
	} else if (speed > 1024) {
		buf << (speed / (1024)) << " KB/s";
	} else {
		buf << speed << "  B/s";
	}
	elapsed = (now.tv_sec + now.tv_usec / 1000000.0) - (this->p_begin.tv_sec + this->p_begin.tv_usec / 1000000.0);
	buf2 << indicator << " " << "[";
	for (int i = 0; i < 40; ++i) {
		if (percent * 40 / 100 > i) {
			buf2 << "=";
		} else {
			buf2 << " ";
		}
	}
	buf2 << "] " << std::setw(3) << percent << "% ";
	buf2 << buf.str() << " ";
	buf2 << std::setw(5) << (elapsed / 3600) << ":";
	buf2 << std::setfill('0') << std::setw(2) << ((elapsed % 3600) / 60) << ":";
	buf2 << std::setfill('0') << std::setw(2) << ((elapsed % 3600) % 60);
	std::cout << "\r" << buf2.str() << "\r" << std::flush;
	
	if (indicator == "|") indicator = "/";
	else if (indicator == "/") indicator = "-";
	else if (indicator == "-") indicator = "\\";
	else if (indicator == "\\") indicator = "|";
}

}

using namespace UploadS3;

static gchar *a_config = NULL;
static gboolean a_test = false;
static gboolean a_continue = false;
static gint a_delete = -1;
static gboolean a_verbose = false;
static gboolean a_progress = false;
static gboolean a_keep = false;

static GOptionEntry entries[] =
{
  { "config", 'c', 0, G_OPTION_ARG_STRING, &a_config, "Configuration file", NULL },
  { "test", 't', 0, G_OPTION_ARG_NONE, &a_test, "Exit with status 0 if file exists, 1 otherwise", NULL },
  { "continue", 'C', 0, G_OPTION_ARG_NONE, &a_continue, "Continue existing upload if any", NULL },
  { "keep", 'k', 0, G_OPTION_ARG_NONE, &a_keep, "Keep existing file (overwrite by default)", NULL },
  { "delete", 'd', 0, G_OPTION_ARG_INT, &a_delete, "Delete existing uploads in progress older than M days (0 stand for all)", "M" },
  { "progress", 'p', 0, G_OPTION_ARG_NONE, &a_progress, "Show upload progress", NULL },
  { "verbose", 'v', 0, G_OPTION_ARG_NONE, &a_verbose, "Verbose operation", NULL },
  { NULL }
};

int main(int argc, char **argv) {
    GError *error = NULL;
    GOptionContext *context;
    Job *job;
    std::string file_arg, prefix;
	bool exists;
	
    context = g_option_context_new("- Amazon S3 upload utility");
    g_option_context_set_help_enabled(context, true);
    g_option_context_add_main_entries(context, entries, NULL);
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_print("option parsing failed: %s\n", error->message);
        return 2;
    }
    if (!a_config) {
        std::cerr << "Required argument missed: -c <config_file>" << std::endl;
        return 2;
	}
    if (argc == 1 && a_delete < 0) {
        std::cerr << "Required argument missed: file to upload or test" << std::endl;
        return 2;
    }
    if (argc > 1) {
		file_arg = argv[1];
	}
	if (argc > 2) {
		prefix = argv[2];
	}
	
	// std::cout << "a_config: " << a_config << " a_test: " << a_test << " a_continue: " << a_continue << " a_delete: " << a_delete << " a_verbose: " << a_verbose << " a_progress: " << a_progress << " a_keep: " << a_keep << " file_arg: " << file_arg << " prefix: " << prefix << std::endl;
	// return 0;
	
	job = new Job(a_config, a_verbose, a_progress);
	if (a_delete >= 0) {
		if (!job->deleteOldUploads(a_delete)) {
			return 2;
		}
	}
	if (file_arg != "") {
		if (a_test) {
			if (!job->test(file_arg, prefix, exists)) {
				return 2;
			}
			if (exists) {
				return 0;
			} else {
				return 1;
			}
		} else {
			if (!job->upload(file_arg, prefix, a_continue, a_keep)) {
				return 2;
			}
		}
	}
    
    return 0;
}
