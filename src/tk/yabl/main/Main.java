package tk.yabl.main;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
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
import java.util.Random;
import java.util.function.Consumer;

import org.apache.commons.io.IOUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bson.BSONObject;
import org.bson.BasicBSONObject;
import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonNull;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.ini4j.Wini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
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
	public static String bottoken = null;
	public static String secret = null;
	public static String gresecret = null;
	public Map<String,JsonObject> loggedUsers = new HashMap<>();
	public final static Logger logger = LoggerFactory.getLogger("tk.yabl.main.Main");
	public static Map<String,String> mimeMap;
	public static boolean debug = false;
	static {
	    mimeMap = new HashMap<>();
	    mimeMap.put("html", "text/html");
	    mimeMap.put("css", "text/css");	
	    mimeMap.put("jpg", "image/jpeg");
	    mimeMap.put("jpeg", "image/jpeg");
	    mimeMap.put("gif", "image/gif");
	    mimeMap.put("js", "application/javascript");
	    mimeMap.put("png", "image/png");
	}
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
            debug = Boolean.parseBoolean(config.get("config").get("debug", "false"));
            bottoken = config.get("config","bottoken");
            secret = config.get("config","clientsecret");
            gresecret = config.get("config", "gresecret");
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
        	Map<String,String> data = new HashMap<>();
        	try {
				session.parseBody(data);
			} catch (IOException e) {
				logger.error("Exception in processing request:",e);
				return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
			} catch (ResponseException e) {
				return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
			}
        	String authorization = session.getHeaders().getOrDefault("authorization","").replaceAll("[^\\w]","");
        	boolean apiToken = false;
        	Document tokenData = new Document();
        	if(db.getCollection("users").find(Document.parse("{\"token\":\""+authorization+"\"}")).first() != null) {
        		apiToken = true;
        		tokenData = db.getCollection("users").find(Document.parse("{\"token\":\""+authorization+"\"}")).first();
        	}
        	if(!apiToken && authorization.length() > 1 && !this.loggedUsers.containsKey(authorization)) {
				return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Authorization is invalid. Please relog.\"}");
        	}
        	if(session.getUri().startsWith("/api/whoami")) {
        		if(authorization != null && (this.loggedUsers.containsKey(authorization))) {
        			JsonObject r = this.loggedUsers.get(authorization);
            		return newFixedLengthResponse(Status.OK,"application/json",r.toString());
            	}
				return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Authorization is invalid. Please relog.\"}");
        	} else if(session.getUri().startsWith("/api/token/")){
        		if(session.getUri().startsWith("/api/token/invalidate")) {
        			if(apiToken) {
	        			Document updatedData = Document.parse(tokenData.toJson());
	        			updatedData.put("token", null);
	        			db.getCollection("users").replaceOne(tokenData,updatedData);
	    				return newFixedLengthResponse(Status.OK,"application/json","{\"error\":true,\"message\":\"Token invalidated belonging to " + tokenData.getString("userid")+"\"}");
	    			}
					return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":false,\"message\":\"Token is not an API token, or otherwise invalid.\"}");
        		} else if(session.getUri().startsWith("/api/token/generate")) {
        			if(authorization != null && (this.loggedUsers.containsKey(authorization))) {
        				JsonObject r = this.loggedUsers.get(authorization);
        				Document user = db.getCollection("users").find(Document.parse("{\"userid\":\""+r.get("id").getAsString()+"\"}")).first();
            			if(user.containsKey("token")) {
                    		return newFixedLengthResponse(Status.OK,"text/plain",user.getString("token"));
            			}
						String token = generate(64);
						user.put("token", token);
						db.getCollection("users").replaceOne(Document.parse("{\"userid\":\""+r.get("id").getAsString()+"\"}"),user);
						return newFixedLengthResponse(Status.OK,"text/plain",user.getString("token"));
                	}
					return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":false,\"message\":\"Token is not an User token, or otherwise invalid.\"}");
        		}
        	} else if(session.getUri().startsWith("/api/bot")) {
        		if(session.getUri().startsWith("/api/bot/")) {
        			if(session.getMethod() == Method.GET) { 
        				if(session.getUri().split("/").length < 4) return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"No bot specified.\"}");
        				if(canParse(session.getUri().split("/")[3])) {
        					String id = session.getUri().split("/")[3];
        					Document d = new Document();
        					d.put("id", new BsonString(id));
        					Document bot = db.getCollection("bots").find(d).first();
        					if(bot != null) {
        						bot.remove("_id");
        						if(authorization != null && this.loggedUsers.containsKey(authorization)) {
        							if(!bot.get("owners", Document.class).containsKey(this.loggedUsers.get(authorization).get("id").getAsString()) 
        									&& (!this.loggedUsers.get(authorization).has("admin") 
        									&& !this.loggedUsers.get(authorization).get("admin").getAsBoolean())) {
        								bot.remove("modnote");
        							}
        						} else {
        							bot.remove("modnote");
        						}
        						return newFixedLengthResponse(Status.OK,"application/json",bot.toJson());
        					}
							return newFixedLengthResponse(Status.NOT_FOUND,"application/json","{\"error\":true,\"message\":\"Bot doesn't exist.\"}");
        				}
        			} else if(session.getMethod() == Method.POST) {
        				if(authorization != null && (this.loggedUsers.containsKey(authorization) || apiToken)) {
        					JsonObject json;
        					try {
        						json = new JsonParser().parse(ifnull(data.get("postData"),"{}").toString()).getAsJsonObject();
        					} catch(JsonSyntaxException e) {
								return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
        					} catch(IllegalStateException e) {
        						return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
        					}
	        				if(session.getUri().split("/").length > 4) {
	        					if(session.getUri().split("/")[4].equals("add")){
	        						if(apiToken) return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
	        						if(json.has("id") && json.has("prefix") && json.has("help") && json.has("desc") && json.has("body") && json.has("gresponse")) {
	        							try(CloseableHttpClient httpclient = HttpClients.createDefault()){
		        							HttpPost httppost = new HttpPost("https://www.google.com/recaptcha/api/siteverify?secret="+gresecret+"&response="+json.get("gresponse").getAsString());
		        							JsonObject response;
		        							Document document = new Document();
		        							try {
												response = new JsonParser().parse(EntityUtils.toString(httpclient.execute(httppost).getEntity())).getAsJsonObject();
											} catch (Exception e) {
												return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
											}
	        								if(!response.get("success").getAsBoolean() && !debug) {
	    										return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Invalid grecaptcha response.\"}");
	        								}
		        							try {
		        								
												document.put("id", json.get("id").getAsString());
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
												document.put("verified",false);
											} catch (Exception e1) {
												return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e1.getClass().getTypeName()+": "+e1.getMessage()+"\"}");
											}
		        							BSONObject owners = new BasicBSONObject();
		        							owners.put(this.loggedUsers.get(authorization).get("id").getAsString(),this.loggedUsers.get(authorization).get("username").getAsString() + "#" + this.loggedUsers.get(authorization).get("discriminator").getAsString());
		        							document.put("owners", owners);
		        							HttpGet httpget = new HttpGet("https://discordapp.com/api/v6/users/" + json.get("id").getAsString());
		        							httpget.setHeader("Content-Type", "application/json");
		        							httpget.setHeader("Authorization", "Bot "+bottoken);
		        							try {
												response = new JsonParser().parse(EntityUtils.toString(httpclient.execute(httpget).getEntity())).getAsJsonObject();
												if(response.has("username") && response.get("id").getAsString().equals(json.get("id").getAsString()) && response.has("bot")) {
													document.put("username", response.get("username").getAsString());
													document.put("avatar", response.get("avatar")==null?"":response.get("avatar").getAsString());
													Document user = db.getCollection("users").find(new BsonDocument().append("userid", new BsonString(this.loggedUsers.get(authorization).get("id").getAsString()))).first();
													@SuppressWarnings("unchecked")
													List<String> bots = (List<String>)user.get("bots");
													bots.add(json.get("id").getAsString());
													List<BsonValue> botsUpdated = new ArrayList<>();
													bots.forEach(a->{botsUpdated.add(new BsonString(a));});
													BsonArray list = new BsonArray();
													list.addAll(botsUpdated);
													ObjectId id = (ObjectId) user.get("_id");
													user.put("bots", list);
													Document userF = new Document();
													userF.put("_id", id);
													db.getCollection("users").replaceOne(userF, user);
													db.getCollection("bots").insertOne(document);
													document.remove("_id");
													HttpPut httpput = new HttpPut("https://discordapp.com/api/v6/guilds/523523486719803403/members/"+this.loggedUsers.get(authorization).get("id").getAsString());
													httpput.setHeader("Content-Type", "application/json");
				        							httpput.setHeader("Authorization", "Bot "+bottoken);
				        							StringEntity ent = new StringEntity("{\"access_token\":\""+authorization+"\"}");
				        							httpput.setEntity(ent);
													botUpdate(document.getString("id"),new String[]{this.loggedUsers.get(authorization).get("id").getAsString()},0,this.loggedUsers.get(authorization).get("id").getAsString());
													return newFixedLengthResponse(Status.CREATED,"application/json",document.toJson());
												}
												return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Bot doesn't exist.\"}");
											} catch(MongoWriteException e) {
												if(e.getCode() == 11000) {
													return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Bot already exists.\"}");
												}
												logger.error("Exception in processing request:",e);
												return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
											}catch (Exception e) {
												logger.error("Exception in processing request:",e);
												return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
											}
		        						} catch (IOException e2) {
		        							logger.error("Exception in processing request:",e2);
											return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Exception "+e2.getClass().getTypeName()+": "+e2.getMessage()+"\"}");
										}
	        						}
	        					} else if(session.getUri().split("/")[4].equals("edit")){
	        						if(apiToken) return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
	        						String id = session.getUri().split("/")[3].replaceAll("[^\\w]","");
	        						Document bot = db.getCollection("bots").find(Document.parse("{\"id\":\""+id+"\"}")).first();
	        						if(bot == null) {
										return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Target bot does not exist.\"}");
	        						}
	        						Document owners = bot.get("owners", Document.class);
	        						if(!owners.keySet().contains(this.loggedUsers.get(authorization).get("id").getAsString()) && this.loggedUsers.get(authorization).get("admin").getAsString() == null) {
	        		            		return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
	        						}
	        						Document document = Document.parse(bot.toJson());
        							try {
										if(json.get("prefix") != null){document.put("prefix", json.get("prefix").getAsString());} else {document.put("prefix", bot.get("prefix"));}
										if(json.get("help") != null){document.put("help", json.get("help").getAsString());} else {document.put("help", bot.get("help"));}
										if(json.get("body") != null){document.put("body", json.get("body").getAsString());} else {document.put("body", bot.get("body"));}
										if(json.get("desc") != null){document.put("desc", json.get("desc").getAsString());} else {document.put("desc", bot.get("desc"));}
										if(json.get("website") != null){document.put("website", json.get("website").getAsString());} else {document.put("website", bot.get("website"));}
										if(json.get("support") != null){document.put("support", json.get("support").getAsString());} else {document.put("support", bot.get("support"));}
										if(json.get("git") != null){document.put("git", json.get("git").getAsString());} else {document.put("git", bot.get("git"));}
										if(json.get("library") != null){document.put("library", json.get("library").getAsString());} else {document.put("library", bot.get("library"));}
										if(json.get("modnote") != null){document.put("modnote", json.get("modnote").getAsString());} else {document.put("modnote", bot.get("modnote"));}
									} catch (Exception e1) {
										logger.error("error",e1);
										return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e1.getClass().getTypeName()+": "+e1.getMessage()+"\"}");
									}
        							db.getCollection("bots").replaceOne(bot, document);
									botUpdate(document.getString("id"),owners.keySet().toArray(new String[0]),1,this.loggedUsers.get(authorization).get("id").getAsString());
									document.remove("_id");
									return newFixedLengthResponse(Status.OK,"application/json",document.toJson());
	        					} else if(session.getUri().split("/")[4].equals("stats")){
	        						if(apiToken) {
	        							String id = session.getUri().split("/")[3].replaceAll("[^\\w]","");
		        						Document bot = db.getCollection("bots").find(Document.parse("{\"id\":\""+id+"\"}")).first();
		        						if(bot == null) {
											return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Target bot does not exist.\"}");
		        						}
		        						Document owners = bot.get("owners", Document.class);
		        						if(!owners.keySet().contains(tokenData.getString("userid"))) {
		        		            		return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
		        						}
		        						if(!json.has("guildCount")) return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"JSON does not have guildCount property.\"}");
		        						if(!canParse(json.get("guildCount").getAsString())) return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Property guildCount is not a valid number.\"}");
		        						if(Integer.parseInt(json.get("guildCount").getAsString().split("\\.")[0].substring(0, Math.min(json.get("guildCount").getAsString().split("\\.")[0].length(), 9))) < 0) 
		        							return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Property guildCount must be greater than or equal to zero.\"}");
		        						bot.put("guildCount", Integer.parseInt(json.get("guildCount").getAsString().split("\\.")[0].substring(0, Math.min(json.get("guildCount").getAsString().split("\\.")[0].length(), 9))));
		        						db.getCollection("bots").replaceOne(Document.parse("{\"id\":\""+id+"\"}"), bot);
		        						bot.remove("_id");
		        						return newFixedLengthResponse(Status.OK,"application/json",bot.toJson());
		        					}
									return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
	        					} else if(session.getUri().split("/")[4].equals("delete")){
	        						if(apiToken) return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
	        						String id = session.getUri().split("/")[3].replaceAll("[^\\w]","");
	        						Document bot = db.getCollection("bots").find(Document.parse("{\"id\":\""+id+"\"}")).first();
	        						if(bot == null) {
										return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Target bot does not exist.\"}");
	        						}
	        						Document owners = bot.get("owners", Document.class);
	        						if(owners.keySet().contains(this.loggedUsers.get(authorization).get("id").getAsString()) || this.loggedUsers.get(authorization).get("admin") != null) {
	        							Document user = db.getCollection("users").find(Document.parse("{\"userid\":\""+this.loggedUsers.get(authorization).get("id").getAsString()+"\"}")).first();
	        							if(user != null) {
	        								ArrayList<?> bots = user.get("bots", ArrayList.class);
		        							bots.remove(id);
		        							user.put("bots", bots);
		        							db.getCollection("users").replaceOne(Document.parse("{\"userid\":\""+this.loggedUsers.get(authorization).get("id").getAsString()+"\"}"), user);
		        							db.getCollection("bots").deleteOne(bot);
		        							botUpdate(bot.getString("id"),owners.keySet().toArray(new String[0]),2,this.loggedUsers.get(authorization).get("id").getAsString());
		        							return newFixedLengthResponse(Status.OK,"application/json","{\"error\":false,\"message\":\"Bot deleted.\"}");
	        							}
	        							db.getCollection("bots").deleteOne(bot);
	        							return newFixedLengthResponse(Status.OK,"application/json","{\"error\":false,\"message\":\"Orphaned bot deleted.\"}");
	        						}
									return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
	        					} else if(session.getUri().split("/")[4].equals("verify")){
	        						if(apiToken || this.loggedUsers.get(authorization).get("admin") == null) 
	        							return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to modify this object.\"}");
	        						String id = session.getUri().split("/")[3].replaceAll("[^\\w]","");
	        						Document bot = db.getCollection("bots").find(Document.parse("{\"id\":\""+id+"\"}")).first();
	        						if(bot == null) {
										return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Target bot does not exist.\"}");
	        						}
	        						Document owners = bot.get("owners", Document.class);
	        						bot.put("verified", true);
        							db.getCollection("bots").replaceOne(Document.parse("{\"id\":\""+id+"\"}"), bot);
        							botUpdate(bot.getString("id"),owners.keySet().toArray(new String[0]),3,this.loggedUsers.get(authorization).get("id").getAsString());
        							return newFixedLengthResponse(Status.OK,"application/json","{\"error\":false,\"message\":\"Bot verified.\"}");
	        					}
	    					}
        				} else {
							return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to access this object.\"}");
                    	}
        			}
        		} else if(session.getUri().startsWith("/api/bots")) {
        			if(session.getUri().startsWith("/api/bots/user/")) {
            			try {
    						if(session.getUri().startsWith("/api/bots/user/@me")) {
    							if(authorization != null && (this.loggedUsers.containsKey(authorization) || apiToken)) {
    								Document user = db.getCollection("users").find(Document.parse("{\"userid\":\""+this.loggedUsers.get(authorization).get("id").getAsString()+"\"}")).first();
    								List<String> botIds = new ArrayList<>();
    								List<String> bots = new ArrayList<>();
    								Document d = new Document();
    								Document b = new Document();
    								logger.info(user.toString());
    								if(user.get("bots") instanceof ArrayList<?>) {
										((ArrayList<?>)user.get("bots")).forEach((a->{botIds.add(a.toString());}));
										b.put("$in", botIds);
	    								d.put("id",b);
									} else {
										return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Bots not instance of ArrayList.\"}");
									}
    								db.getCollection("bots").find(d).forEach((Consumer<Document>)a->{a.remove("_id");bots.add(a.toJson());});
    	            				return newFixedLengthResponse(Status.OK,"application/json","{\"id\":\""+user.getString("userid")+"\",\"userscrim\":\""+user.getString("userscrim")+"\",\"avatar\":\""+user.getString("avatar")+"\",\"bots\":["+String.join(",", bots)+"]}");
    							}
								return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to access this object.\"}");
    						} else if(session.getUri().split("/api/bots/user/")[1].matches("\\d{17,21}")) {
    								Document user = db.getCollection("users").find(new BsonDocument().append("userid", new BsonString(session.getUri().split("/")[4]))).first();
    								BsonArray botIds = new BsonArray();
    								List<String> bots = new ArrayList<>();
    								Document d = new Document();
    								BasicBSONObject b = new BasicBSONObject();
    								if(user.get("bots") instanceof ArrayList<?>) {
										((ArrayList<?>)user.get("bots")).forEach((a->{botIds.add(new BsonString(a.toString()));}));
										b.put("$in", botIds);
	    								d.put("id",b);
									} else {
										return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Bots not instance of ArrayList.\"}");
									}
    								db.getCollection("bots").find(d).forEach((Consumer<Document>)a->{a.remove("_id");bots.add(a.toJson());});
    	            				return newFixedLengthResponse(Status.OK,"application/json","{\"id\":\""+user.getString("userid")+"\",\"userscrim\":\""+user.getString("userscrim")+"\",\"avatar\":\""+user.getString("avatar")+"\",\"bots\":["+String.join(",", bots)+"]}");
    						}
    					}catch (ArrayIndexOutOfBoundsException e) {
							return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
    					}
            		} else if(session.getUri().startsWith("/api/bots/all")) {
            			if(authorization != null && (this.loggedUsers.containsKey(authorization) || apiToken)) {
            				List<String> bots = new ArrayList<>();
            				db.getCollection("bots").find().forEach((Consumer<Document>)a->{a.remove("_id");bots.add(a.toJson());});
            				return newFixedLengthResponse(Status.OK,"application/json","["+String.join(",", bots)+"]");
            			}
						return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to access this object.\"}");
            		} else if(session.getUri().startsWith("/api/bots/page")) {
            			JsonObject json;
            			try {
    						json = new JsonParser().parse(ifnull(data.get("postData"),"{}").toString()).getAsJsonObject();
    					} catch(JsonSyntaxException e) {
    						return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
    					} catch(IllegalStateException e) {
    						return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
    					}
            			List<String> bots = new ArrayList<>();
            			Document d = new Document();
            			Document sort = new Document();
            			if(json.has("search")) {
            				Document d2 = new Document();
                			d2.put("$search", json.get("search") != null ? json.get("search").getAsString() : "");
                			d.put("$text", d2);
                			Document sort2 = new Document();
                			sort2.put("$meta", "textScore");
                			sort.put("score",sort2);
            			}
        				db.getCollection("bots").find(d).projection(sort).sort(sort).skip(json.get("page") != null ? json.get("page").getAsInt()*20 : 0).limit(20).forEach((Consumer<Document>)a->{a.remove("_id");bots.add(a.toJson());});
        				long pages = db.getCollection("bots").countDocuments(d);
        				return newFixedLengthResponse(Status.OK,"application/json","{\"pages\":\""+(int)Math.floor(pages/20)+"\",\"results\":\""+pages+"\",\"bots\":["+String.join(",", bots)+"]}");
            		} else if(session.getUri().startsWith("/api/bots/unverified")) {
            			if(authorization != null && (this.loggedUsers.containsKey(authorization) || apiToken)) {
            				JsonObject json;
                			try {
        						json = new JsonParser().parse(ifnull(data.get("postData"),"{}").toString()).getAsJsonObject();
        					} catch(JsonSyntaxException e) {
        						return newFixedLengthResponse(Status.BAD_REQUEST,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
        					} catch(IllegalStateException e) {
        						return newFixedLengthResponse(Status.INTERNAL_ERROR,"application/json","{\"error\":true,\"message\":\"Exception "+e.getClass().getTypeName()+": "+e.getMessage()+"\"}");
        					}
                			List<String> bots = new ArrayList<>();
                			Document d = Document.parse("{\"verified\":false}");
            				db.getCollection("bots").find(d).skip(json.get("page") != null ? json.get("page").getAsInt()*20 : 0).limit(20).forEach((Consumer<Document>)a->{a.remove("_id");bots.add(a.toJson());});
            				long pages = db.getCollection("bots").countDocuments(d);
            				return newFixedLengthResponse(Status.OK,"application/json","{\"pages\":\""+(int)Math.floor(pages/20)+"\",\"results\":\""+pages+"\",\"bots\":["+String.join(",", bots)+"]}");
            			}
						return newFixedLengthResponse(Status.UNAUTHORIZED,"application/json","{\"error\":true,\"message\":\"Token does not have permission to access this object.\"}");
            		} else {
						List<String> bots = new ArrayList<>();
						Document[] aggregateArray = {Document.parse("{ $match : {\"verified\":true,\"guildCount\":{\"$exists\":true},\"support\":{\"$type\":2}}}"),
								Document.parse("{ $sample : { size: 20 } }]")};
						db.getCollection("bots").aggregate(Arrays.asList(aggregateArray)).forEach((Consumer<Document>)a->{a.remove("_id");bots.add(a.toJson());});
						return newFixedLengthResponse(Status.OK,"application/json","["+String.join(",", bots)+"]");
            		}
        		}
        		
        	}
			return newFixedLengthResponse(Status.NOT_FOUND,"application/json","{\"error\":true,\"message\":\"Requested REST endpoint did not exist.\"}");
        } else if(session.getUri().startsWith("/login")) {
        	Map<String,List<String>> params = session.getParameters();
        	if(!params.containsKey("code")) {
        		String authuri = "https://discordapp.com/api/oauth2/authorize?client_id=521481605467078667&redirect_uri=https://yabl.xyz/login&response_type=code&scope=identify%20guilds.join";
        		Response response = newFixedLengthResponse(Status.REDIRECT_SEE_OTHER,"text/html","We're redirecting you to discord. If you dont get redirected, <a href=\""+authuri+"\">click here</a> or go to the following link manually:<br/>"+authuri);
        		response.addHeader("Location", authuri);
        		return response;
        	}
        	try(CloseableHttpClient httpclient = HttpClients.createDefault()) {
				HttpPost httppost = new HttpPost("https://discordapp.com/api/oauth2/token");
				List <NameValuePair> nvps = new ArrayList <>();
				nvps.add(new BasicNameValuePair("code", params.get("code").get(0)));
				nvps.add(new BasicNameValuePair("client_id", "521481605467078667"));
				nvps.add(new BasicNameValuePair("client_secret", secret));
				if(!debug) {
					nvps.add(new BasicNameValuePair("redirect_uri", "https://yabl.xyz/login"));
				} else {
					nvps.add(new BasicNameValuePair("redirect_uri", "http://localhost/login"));
				}
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
					Document user = db.getCollection("users").find(new BsonDocument().append("userid", new BsonString(uInfo.get("id").getAsString()))).first();
					if(user != null) {
						if(user.getBoolean("admin",false)) {
							uInfo.addProperty("admin", true);
						}
						this.loggedUsers.put(response.get("access_token").getAsString(), uInfo);
						String rediruri = "https://yabl.xyz/dashboard?code="+response.get("access_token").getAsString();
						Response r = newFixedLengthResponse(Status.REDIRECT_SEE_OTHER,"text/html","Login success. If you dont get redirected, <a href=\""+rediruri+"\">click here</a> or go to the following link manually:<br/>"+rediruri);
						r.addHeader("Location", rediruri);
						user.put("avatar", uInfo.get("avatar").getAsString());
						db.getCollection("users").replaceOne(new BsonDocument().append("userid", new BsonString(uInfo.get("id").getAsString())), user);
						return r;
					}
					user = new Document();
					user.append("userid", uInfo.get("id").getAsString());
					user.append("bots", new BsonArray());
					user.append("avatar", uInfo.get("avatar").getAsString());
					user.append("userscrim", uInfo.get("username").getAsString() + "#" + uInfo.get("discriminator").getAsString());
					db.getCollection("users").insertOne(user);
					this.loggedUsers.put(response.get("access_token").getAsString(), uInfo);
					String rediruri =  "https://yabl.xyz/dashboard?code="+response.get("access_token").getAsString();
					Response r = newFixedLengthResponse(Status.REDIRECT_SEE_OTHER,"text/html","User Created, Login success. If you dont get redirected, <a href=\""+rediruri+"\">click here</a> or go to the following link manually:<br/>"+rediruri);
					r.addHeader("Location", rediruri);
					return r;
				}
				return newFixedLengthResponse(Status.INTERNAL_ERROR,"text/plain", "Something went wrong in login, please try again.");
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
        } else if(session.getUri().startsWith("/bot/")) {
        	String response;
        	String mime = "text/html";
			Status status = Status.OK;
			try {
				if(session.getUri().split("/bot/")[1].matches("\\d{17,21}")) {
					String id = session.getUri().split("/bot/")[1].replaceAll("[^\\w]","");
					if(db.getCollection("bots").find(Document.parse("{\"id\":\""+id+"\"}")).first() == null) throw new NoSuchFileException("");
					response = String.join("\n", Files.readAllLines(Paths.get("./www/bot.html")));
				} else {
					throw new NoSuchFileException("");
				}
			} catch (NoSuchFileException e) {
				logger.warn("Bot page not found", e);
				try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/404.html")));
					mime = "text/html";
					status = Status.NOT_FOUND;
				} catch (NoSuchFileException e1) {
					logger.debug("Error document not found", e1);
					mime = "text/html";
					response = "<h1>404: Not Found</h1><br/><h3>The requested URL "+session.getUri()+" was not found on this server.</h3><br/>Additionally, the 404 error document was not found.";
					status = Status.NOT_FOUND;
				}
        		catch (IOException e1) {
	        		logger.error("IO Exception in bot page:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
				return newFixedLengthResponse(status,mime,response);
			}  catch(AccessDeniedException e) {
				logger.error("Bot page access forbidden", e);
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/403.html")));
					mime = "text/html";
					status = Status.FORBIDDEN;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found", e1);
					mime = "text/html";
					response = "<h1>403: Forbidden</h1><br/><h3>The requested URL "+session.getUri()+" was denied access to by the filesystem.</h3><br/>Additionally, the 403 error document was not found.";
					status = Status.FORBIDDEN;
				}
        		catch (IOException e1) {
	        		logger.error("IO exception in bot page:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
        	} catch (IOException e) {
        		logger.error("IO exception in bot page", e);
        		try {
        			mime = "text/html";
					response = String.join("\n", Files.readAllLines(Paths.get("./www/500.html")));
					status = Status.INTERNAL_ERROR;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found:",e1);
					mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk<br/>Additionally, the 500 error document was not found.";
					status = Status.INTERNAL_ERROR;
				}
        		catch (IOException e1) {
	        		logger.error("IO Exception in bot page:",e1);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					mime = "text/html";
					status = Status.INTERNAL_ERROR;
        		}
			}
        	return newFixedLengthResponse(status,mime,response);
		}else if(session.getUri().startsWith("/user/")) {
        	String response;
        	String mime = "text/html";
			Status status = Status.OK;
			try {
				if(session.getUri().split("/user/")[1].matches("\\d{17,21}")) {
					String id = session.getUri().split("/user/")[1].replaceAll("[^\\w]","");
					if(db.getCollection("users").find(Document.parse("{\"userid\":\""+id+"\"}")).first() == null) throw new NoSuchFileException("");
					response = String.join("\n", Files.readAllLines(Paths.get("./www/user.html")));
				} else {
					throw new NoSuchFileException("");
				}
			} catch (NoSuchFileException e) {
				logger.warn("User page not found.", e);
				try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/404.html")));
					mime = "text/html";
					status = Status.NOT_FOUND;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found.", e1);
					mime = "text/html";
					response = "<h1>404: Not Found</h1><br/><h3>The requested URL "+session.getUri()+" was not found on this server.</h3><br/>Additionally, the 404 error document was not found.";
					status = Status.NOT_FOUND;
				}
        		catch (IOException e1) {
	        		logger.error("Exception in processing request:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
				return newFixedLengthResponse(status,mime,response);
			}  catch(AccessDeniedException e) {
				logger.warn("User page access forbidden.", e);
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/403.html")));
					mime = "text/html";
					status = Status.FORBIDDEN;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found.", e1);
					mime = "text/html";
					response = "<h1>403: Forbidden</h1><br/><h3>The requested URL "+session.getUri()+" was denied access to by the filesystem.</h3><br/>Additionally, the 403 error document was not found.";
					status = Status.FORBIDDEN;
				}
        		catch (IOException e1) {
	        		logger.error("IO Exception in user page:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
        	} catch (IOException e) {
        		logger.error("IO Exception in user page.", e);
        		try {
        			mime = "text/html";
					response = String.join("\n", Files.readAllLines(Paths.get("./www/500.html")));
					status = Status.INTERNAL_ERROR;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found.", e1);
					mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk<br/>Additionally, the 500 error document was not found.";
					status = Status.INTERNAL_ERROR;
				}
        		catch (IOException e1) {
	        		logger.error("Exception in processing request:",e1);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					mime = "text/html";
					status = Status.INTERNAL_ERROR;
        		}
			}
        	return newFixedLengthResponse(status,mime,response);
		} else if(session.getUri().startsWith("/edit/")) {
        	String response;
        	String mime = "text/html";
			Status status = Status.OK;
			try {
				if(session.getUri().split("/edit/")[1].matches("\\d{17,21}")) {
					String id = session.getUri().split("/edit/")[1].replaceAll("[^\\w]","");
					if(db.getCollection("bots").find(Document.parse("{\"id\":\""+id+"\"}")).first() == null) throw new NoSuchFileException("");
					response = String.join("\n", Files.readAllLines(Paths.get("./www/edit.html")));
				} else {
					throw new NoSuchFileException("");
				}
			} catch (NoSuchFileException e) {
				logger.warn("Edit page not found.", e);
				try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/404.html")));
					mime = "text/html";
					status = Status.NOT_FOUND;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found.", e1);
					mime = "text/html";
					response = "<h1>404: Not Found</h1><br/><h3>The requested URL "+session.getUri()+" was not found on this server.</h3><br/>Additionally, the 404 error document was not found.";
					status = Status.NOT_FOUND;
				}
        		catch (IOException e1) {
	        		logger.error("IO Exception in edit page:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
				return newFixedLengthResponse(status,mime,response);
			}  catch(AccessDeniedException e) {
				logger.error("Edit page access denied", e);
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/403.html")));
					mime = "text/html";
					status = Status.FORBIDDEN;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found.", e1);
					mime = "text/html";
					response = "<h1>403: Forbidden</h1><br/><h3>The requested URL "+session.getUri()+" was denied access to by the filesystem.</h3><br/>Additionally, the 403 error document was not found.";
					status = Status.FORBIDDEN;
				}
        		catch (IOException e1) {
	        		logger.error("IO Exception in edit page:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
        	} catch (IOException e) {
        		logger.error("IO Exception in edit page.", e);
        		try {
        			mime = "text/html";
					response = String.join("\n", Files.readAllLines(Paths.get("./www/500.html")));
					status = Status.INTERNAL_ERROR;
				} catch (NoSuchFileException e1) {
					logger.warn("Error Document not found.", e1);
					mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk<br/>Additionally, the 500 error document was not found.";
					status = Status.INTERNAL_ERROR;
				}
        		catch (IOException e1) {
        			logger.error("IO Exception in edit page.", e1);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					mime = "text/html";
					status = Status.INTERNAL_ERROR;
        		}
			}
        	return newFixedLengthResponse(status,mime,response);
		} else {
        	String response;
        	Status status = Status.OK;
        	String mime = "text/plain";
        	try {
        		if(session.getUri().equals("/")) {
        			response = String.join("\n", Files.readAllLines(Paths.get("./www/index.html")));
        			mime = "text/html";
        		}
        		else {
        			
        			String uri;
        			if(session.getUri().replaceAll("\\.\\.", "").split("\\.").length > 1) {
        				uri = session.getUri().replaceAll("\\.\\.", "");
        				mime = mimeMap.get(uri.split("\\.")[1]);
        			} else {
        				uri = session.getUri().replaceAll("\\.\\.", "") + ".html";
        				mime = "text/html";
        			}
        			response = String.join("\n", Files.readAllLines(Paths.get("./www/"+uri)));
        		}
        	} catch(NoSuchFileException e) {
        		logger.debug("File not found.", e);
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/404.html")));
					mime = "text/html";
					status = Status.NOT_FOUND;
				} catch (NoSuchFileException e1) {
					logger.warn("Error document not found.", e1);
					mime = "text/html";
					response = "<h1>404: Not Found</h1><br/><h3>The requested URL "+session.getUri()+" was not found on this server.</h3><br/>Additionally, the 404 error document was not found.";
					status = Status.NOT_FOUND;
				}
        		catch (IOException e1) {
	        		logger.error("IO Exception in serve file:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
        	} catch(AccessDeniedException e) {
        		logger.debug("File access forbidden.", e);
        		try {
					response = String.join("\n", Files.readAllLines(Paths.get("./www/403.html")));
					mime = "text/html";
					status = Status.FORBIDDEN;
				} catch (NoSuchFileException e1) {
					logger.warn("Error document not found.", e1);
					mime = "text/html";
					response = "<h1>403: Forbidden</h1><br/><h3>The requested URL "+session.getUri()+" was denied access to by the filesystem.</h3><br/>Additionally, the 403 error document was not found.";
					status = Status.FORBIDDEN;
				}
        		catch (IOException e1) {
	        		logger.error("IO Exception in serve file:",e1);
	        		mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					status = Status.INTERNAL_ERROR;
        		}
        	} catch (IOException e) {
        		logger.error("IO Exception in serve file.", e);
        		try {
        			mime = "text/html";
					response = String.join("\n", Files.readAllLines(Paths.get("./www/500.html")));
					status = Status.INTERNAL_ERROR;
				} catch (NoSuchFileException e1) {
					logger.warn("Error document not found.", e1);
					mime = "text/html";
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk<br/>Additionally, the 500 error document was not found.";
					status = Status.INTERNAL_ERROR;
				}
        		catch (IOException e1) {
        			logger.error("IO Exception in serve file.", e1);
					response = "<h1>500: Internal Server Error</h1><br/><h3>Server encountered an exception.</h3><br/>Try again later, if the problem persists contact the administrator at admin@yabl.tk";
					mime = "text/html";
					status = Status.INTERNAL_ERROR;
        		}
			}
        	return newFixedLengthResponse(status,mime,response);
        }
    }
	public static <T> T ifnull(T input,T ifnull) {
    	return (input != null ? input : ifnull);
    }
	public static boolean canParse(String input) {
		try{
			Double.parseDouble(input);
			return true;
		} catch(NumberFormatException e) {
			e.hashCode();
			return false;
		} 
	}
	public static String generate(int size) {
        String SALTCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() < size) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }
        String saltStr = salt.toString();
        return saltStr;

     }
	private static void botUpdate(String id, String[] owners, int type, String by) {
		try(CloseableHttpClient httpclient = HttpClients.createDefault();) {
			HttpPost httppost = new HttpPost("https://discordapp.com/api/v6/channels/523526083698491432/messages");
			httppost.setHeader("Content-Type", "application/json");
			httppost.setHeader("Authorization","Bot "+bottoken);
			String content = "{\"content\":\"";
			String ownersstring = String.join("> <@", owners);
			switch(type) {
				case 0:
					content = content +"<:yabl_add:523557038291288065> <@"+by+">"+ " Added bot " + "<@"+id+"> (" + id + ") <@&523523933434019860>"; 
					break;
				case 1:
					content = content +"<:yabl_edit:523557038232436736> <@"+by+">"+ " Edited bot " + "<@"+id+"> (" + id + ") By " + "<@"+ownersstring+">"; 
					break;
				case 2:
					content = content +"<:yabl_delete:523557038316322836> <@"+by+">"+ " Deleted bot " + "<@"+id+"> (" + id + ") By " + "<@"+ownersstring+">"; 
					delete(id);
					break;
				case 3:
					content = content +":white_check_mark: <@"+by+">"+ " Verified bot " + "<@"+id+"> (" + id + ") By " + "<@"+ownersstring+">"; 
					verify(id);
					break;
			default:
				return;
			}
			content = content + "\"}";
			httppost.setEntity(new StringEntity(content));
			StringWriter writer = new StringWriter();
			IOUtils.copy(httpclient.execute(httppost).getEntity().getContent(), writer, StandardCharsets.UTF_8);
		} catch (Exception e) {
			logger.error("Failed to post bot update to discord",e);
		}
	}
	private static void delete(String id) {
		try(CloseableHttpClient httpclient = HttpClients.createDefault();) {
			HttpDelete httpdelete = new HttpDelete("https://discordapp.com/api/v6/guilds/523526083698491432/members/"+id);
			httpdelete.setHeader("Content-Type", "application/json");
			httpdelete.setHeader("Authorization","Bot "+bottoken);
			StringWriter writer = new StringWriter();
			IOUtils.copy(httpclient.execute(httpdelete).getEntity().getContent(), writer, StandardCharsets.UTF_8);
		} catch (Exception e) {
			logger.error("Failed to post bot delete to discord",e);
		}
	}
	private static void verify(String id) {
		try(CloseableHttpClient httpclient = HttpClients.createDefault();) {
			HttpPut httpput = new HttpPut("https://discordapp.com/api/v6/guilds/523526083698491432/members/"+id+"/roles/523524003625697290");
			httpput.setHeader("Content-Type", "application/json");
			httpput.setHeader("Authorization","Bot "+bottoken);
			StringWriter writer = new StringWriter();
			IOUtils.copy(httpclient.execute(httpput).getEntity().getContent(), writer, StandardCharsets.UTF_8);
		} catch (Exception e) {
			logger.error("Failed to post bot verify to discord",e);
		}
	}
	
}
