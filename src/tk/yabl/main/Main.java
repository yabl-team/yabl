package tk.yabl.main;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt64;
import org.bson.BsonNull;
import org.bson.BsonString;
import org.bson.Document;
import org.ini4j.Wini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.MongoWriteException;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;

public class Main extends NanoHTTPD {
	public static MongoClient mongo = null;
	public static MongoDatabase db = null;
	public static String token = null;
	public Map<String,JsonObject> loggedUsers = new HashMap<String,JsonObject>();
	public final static Logger logger = LoggerFactory.getLogger("tk.yabl.main.Main");
	public Main(int port) throws IOException {
		super(port);
        start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
        logger.info("Running");
	}
	
	public static void main(String[] args) {
		try {
            Wini config = new Wini(new File("config.ini"));
            int port = Integer.parseInt(config.get("config", "port"));
            String username = config.get("config", "mongousr");
            String password = config.get("config", "mongopwd");
            String source = config.get("config", "mongosrc");
            String database = config.get("config", "mongodtb");
            token = config.get("config","bottoken");
            MongoCredential credential = MongoCredential.createCredential(username, source, password.toCharArray());
            mongo = MongoClients.create(
            		MongoClientSettings.builder()
                            .applyToClusterSettings(builder -> builder.hosts(Arrays.asList(new ServerAddress("localhost", 27017))))
                            .credential(credential)
                            .build());
            db = mongo.getDatabase(database);
            new Main(port);
        } catch (Exception e) {
            logger.error("Error while starting server:", e);
        }
	}
	
	@Override
    public Response serve(IHTTPSession session) {
        if(session.getUri().startsWith("/api/")) {
        	Map<String,String> data = new HashMap<String,String>();
        	try {
				session.parseBody(data);
			} catch (IOException e) {
				logger.error("Exception in processing request:",e);
				return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/plain","");
			} catch (ResponseException e1) {
				return newFixedLengthResponse(Status.BAD_REQUEST,"text/plain","");
			}
        	String authorization = session.getHeaders().get("authorization");
        	if(session.getUri().startsWith("/api/whoami")) {
        		if(authorization != null && loggedUsers.containsKey(authorization)) {
        			JsonObject r = this.loggedUsers.get(authorization);
            		return newFixedLengthResponse(Status.OK,"application/json",r.toString());
            	} else {
            		return newFixedLengthResponse(Status.UNAUTHORIZED,"text/plain","");
            	}
        	} else if(session.getUri().startsWith("/api/bot")) {
        		if(session.getUri().startsWith("/api/bot/")) {
        			if(session.getMethod() == Method.GET) { 
        				if(session.getUri().split("/").length < 4) return newFixedLengthResponse(Status.BAD_REQUEST,"text/plain","");
        				if(session.getUri().split("/")[3].matches("\\d{17,21}")) {
        					 					
        				}
        			} else if(session.getMethod() == Method.POST) {
        				if(authorization != null && loggedUsers.containsKey(authorization)) {
        				JsonObject json = new JsonParser().parse(ifnull(data.get("postData"),"{}").toString()).getAsJsonObject();
	        				if(session.getUri().split("/").length > 4) {
	        					if(session.getUri().split("/")[4].equals("add")){
	        						if(json.has("id") && json.has("prefix") && json.has("help") && json.has("desc") && json.has("body")) {
	        							Document document = new Document();
	        							try {
											document.put("id", json.get("id").getAsLong());
											document.put("prefix", json.get("prefix").getAsString());
											document.put("help", json.get("help").getAsString());
											document.put("desc", json.get("desc").getAsString());
											document.put("body", json.get("body").getAsString());
											Object website = json.get("website") == null ? new BsonNull() : json.get("website").getAsString();
											Object support = json.get("support") == null ? new BsonNull() : json.get("support").getAsString();
											Object git = json.get("git") == null ? new BsonNull() : json.get("git").getAsString();
											Object library = json.get("library") == null ? new BsonNull() : json.get("library").getAsString();
											Object modnote = json.get("modnote") == null ? new BsonNull() : json.get("modnote").getAsString();
											document.put("website", website);
											document.put("support", support);
											document.put("git", git);
											document.put("library", library);
											document.put("modnote", modnote);
										} catch (Exception e1) {
											return newFixedLengthResponse(Status.BAD_REQUEST,"text/plain","");
										}
	        							BsonArray owners = new BsonArray();
	        							owners.add(new BsonInt64(loggedUsers.get(authorization).get("id").getAsLong()));
	        							document.put("owners", owners);
	        							HttpClient httpclient = HttpClients.createDefault();
	        							HttpGet httppost = new HttpGet("https://discordapp.com/api/v6/users/" + json.get("id").getAsString());
	        							httppost.setHeader("Content-Type", "application/json");
	        							httppost.setHeader("Authorization", "Bot "+token);
	        							try {
											JsonObject response = new JsonParser().parse(EntityUtils.toString(httpclient.execute(httppost).getEntity())).getAsJsonObject();
											if(response.has("username") && response.get("id").getAsString().equals(json.get("id").getAsString())) {
												db.getCollection("bots").insertOne(document);
												document.remove("_id");
												return newFixedLengthResponse(Status.CREATED,"application/json",document.toJson());
											} else {
												return newFixedLengthResponse(Status.BAD_REQUEST,"text/plain","Bot doesnt exist.");
											}
										} catch(MongoWriteException e) {
											if(e.getCode() == 11000) {
												return newFixedLengthResponse(Status.BAD_REQUEST,"text/plain","Bot already exists.");
											} else {
												logger.error("Exception in processing request:",e);
												return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/plain","");
											}
										}catch (Exception e) {
											logger.error("Exception in processing request:",e);
											return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/plain","");
										}
	        						}
	        					} else if(session.getUri().split("/")[4].equals("edit")){
	        						
	        					} else if(session.getUri().split("/")[4].equals("stats")){
	        						
	        					} else if(session.getUri().split("/")[4].equals("delete")){
	        						
	        					}
	    					}
        				} else {
                    		return newFixedLengthResponse(Status.UNAUTHORIZED,"text/plain","");
                    	}
        			}
        		} else if(session.getUri().startsWith("/api/bots")) {
        			if(session.getUri().startsWith("/api/bots/user/")) {
            			try {
    						if(session.getUri().startsWith("/api/bots/user/@me")) {
    							if(authorization != null && loggedUsers.containsKey(authorization)) {
    								
    							} else {
    			            		return newFixedLengthResponse(Status.UNAUTHORIZED,"text/plain","");
    			            	}
    						} else if(session.getUri().split("/api/bots/user/")[1].matches("\\d{17,21} ")) {
    							if(authorization != null && loggedUsers.containsKey(authorization)) {
    								
    							} else {
    			            		return newFixedLengthResponse(Status.UNAUTHORIZED,"text/plain","");
    			            	}
    						}
    					}catch (ArrayIndexOutOfBoundsException e) {
    						return newFixedLengthResponse(Status.BAD_REQUEST,"text/plain","");
    					}
            		} else if(session.getUri().startsWith("/api/bots/all")) {
            			if(authorization != null && loggedUsers.containsKey(authorization)) {
            				
            			}else {
                    		return newFixedLengthResponse(Status.UNAUTHORIZED,"text/plain","");
                    	}
            		} else if(session.getUri().startsWith("/api/bots/page/")) {
            			
            		} else {
            			
            		}
        		}
        		
        	}
        	return newFixedLengthResponse(Status.NOT_FOUND,"text/plain","");
        } else if(session.getUri().startsWith("/login")) {
        	Map<String,List<String>> params = session.getParameters();
        	if(!params.containsKey("code")) {
        		Response response = newFixedLengthResponse(Status.REDIRECT_SEE_OTHER,"text/plain","");
        		response.addHeader("Location", "https://discordapp.com/api/oauth2/authorize?client_id=521481605467078667&redirect_uri=http://localhost/login&response_type=code&scope=identify");
        		return response;
        	}
        	try {
				HttpClient httpclient = HttpClients.createDefault();
				HttpPost httppost = new HttpPost("https://discordapp.com/api/oauth2/token");
				List <NameValuePair> nvps = new ArrayList <NameValuePair>();
				nvps.add(new BasicNameValuePair("code", params.get("code").get(0)));
				nvps.add(new BasicNameValuePair("client_id", "521481605467078667"));
				nvps.add(new BasicNameValuePair("client_secret", "3G1Rasipgri5ASRiKDjENEF77sMU9DmH"));
				nvps.add(new BasicNameValuePair("redirect_uri", "http://localhost/login"));
				nvps.add(new BasicNameValuePair("grant_type", "authorization_code"));
				nvps.add(new BasicNameValuePair("scope", "identify"));
				httppost.setHeader("Content-Type", "application/x-www-form-urlencoded");
				httppost.setEntity(new UrlEncodedFormEntity(nvps,StandardCharsets.UTF_8));
				JsonObject response = new JsonParser().parse(EntityUtils.toString(httpclient.execute(httppost).getEntity())).getAsJsonObject();
				if(response.get("access_token") != null) {
					HttpGet getUinfo = new HttpGet("https://discordapp.com/api/v6/users/@me");
					getUinfo.setHeader("Content-Type","application/json");
					getUinfo.setHeader("Authorization","Bearer " + response.get("access_token").getAsString());
					JsonObject uInfo = new JsonParser().parse(EntityUtils.toString(httpclient.execute(getUinfo).getEntity())).getAsJsonObject();
					this.loggedUsers.put(response.get("access_token").getAsString(), uInfo);
					Document user = db.getCollection("users").find(new BsonDocument().append("userid", new BsonString(uInfo.get("id").getAsString()))).first();
					if(user != null) {
						Response r = newFixedLengthResponse(Status.REDIRECT_SEE_OTHER,"text/plain","Login success.");
						r.addHeader("Location", "http://localhost/dashboard?code="+response.get("access_token").getAsString());
						return r;
					} else {
						user = new Document();
						user.append("userid", uInfo.get("id").getAsString());
						user.append("bots", new BsonArray());
						db.getCollection("users").insertOne(user);
						Response r = newFixedLengthResponse(Status.REDIRECT_SEE_OTHER,"text/plain","User created, Login success.");
						r.addHeader("Location", "http://localhost/dashboard?code="+response.get("access_token").getAsString());
						return r;
					}
				} else {
					return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/html", "Something went wrong in login, try again.");
				}
			} catch(Exception e) {
				logger.error("Exception in processing request:",e);
				try {
					return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/html", String.join("\n", Files.readAllLines(Paths.get("./www/500.html"))));
				} catch (NoSuchFileException e1) {
					logger.error("Exception in processing request:",e1);
					return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/html","<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk<br/>Additionally, the 500 error document was not found.");
				}
        		catch (IOException e1) {
	        		logger.error("Exception in processing request:",e1);
					return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/html","<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk");
        		}
			}
        	//return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/plain","Something went wrong in login, try again.");
        } else {
        	String response;
        	Status status = Status.OK;
        	try {
        		if(session.getUri().equals("/")) {
        			response = String.join("\n", Files.readAllLines(Paths.get("./www/index.html")));
        		}
        		else {
        			response = String.join("\n", Files.readAllLines(Paths.get("./www/"+session.getUri().replaceAll("\\.\\.", ""))));
        		}
        	} catch(NoSuchFileException e) {
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/404.html")));
					status = Status.NOT_FOUND;
				} catch (NoSuchFileException e1) {
					response = "<h1>404: Not Found</h1><br/><h3>The requested URL "+session.getUri()+" was not found on this server.</h3><br/>Additionally, the 404 error document was not found.";
					status = Status.NOT_FOUND;
				}
        		catch (IOException e1) {
	        		logger.error("Exception in processing request:",e);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
        	} catch(AccessDeniedException e) {
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/403.html")));
					status = Status.FORBIDDEN;
				} catch (NoSuchFileException e1) {
					response = "<h1>403: Forbidden</h1><br/><h3>The requested URL "+session.getUri()+" was denied access to by the filesystem.</h3><br/>Additionally, the 403 error document was not found.";
					status = Status.FORBIDDEN;
				}
        		catch (IOException e1) {
	        		logger.error("Exception in processing request:",e);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
        	} catch (IOException e) {
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/500.html")));
					status = Status.INTERNAL_ERROR;
				} catch (NoSuchFileException e1) {
					logger.error("Exception in processing request:",e);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk<br/>Additionally, the 500 error document was not found.";
					status = Status.INTERNAL_ERROR;
				}
        		catch (IOException e1) {
	        		logger.error("Exception in processing request:",e);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
			}
        	return newFixedLengthResponse(status,"text/html",response);
        }
    }
	public <T> T ifnull(T input,T ifnull) {
    	return (input != null ? input : ifnull);
    }
}