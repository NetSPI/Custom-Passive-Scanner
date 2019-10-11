package customPassiveScanner;

import burp.IBurpExtenderCallbacks;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

@JsonSerialize(using = IssueCollectionStoreSerializer.class)
public class IssueCollectionStore {

//    private static ArrayList<IssueCollection> collections;
    private static HashMap<String, IssueCollection> collections;
    private static IBurpExtenderCallbacks callbacks;

    private static final String collectionStoreSettingName = "findCloudServiceRefs.collections";

    public static void init(IBurpExtenderCallbacks callbacks) {
        IssueCollectionStore.collections = new HashMap<String, IssueCollection>();
        IssueCollectionStore.callbacks = callbacks;
        Logger.log("Loading collections...");
        loadCollections();
    }

    public static Collection<IssueCollection> getCollections() {
        return collections.values();
    }

    public static IssueCollection getCollection(String fileLocation) {
        return collections.get(fileLocation);
    }

    private static IssueCollection getCollectionFromFile(File file) {
        IssueCollection collection = null;
        try {
            collection = IssueCollectionParser.parseIssuesFile(file);
        } catch (IOException e) {
            Logger.log("Failed to read " + file.getName());
        }
        return collection;
    }

    public static IssueCollection addCollection(File file) {
        // Default a new collection to be enabled
        return addCollection(file, true);
    }

    public static IssueCollection addCollection(File file, boolean inUse) {
        if (collections.containsKey(file.getPath())) {
            // Collection store already contains this collection
            Logger.log("Store already contains collection from " + file.getPath());
            return null;
        }

        Logger.log("Loading collection from " + file.getPath());
        IssueCollection collection = getCollectionFromFile(file);

        // Decided to default this to set inUse
        collection.setInUse(inUse);

        collections.put(file.getPath(), collection);
        storeCollectionPaths();
        return collection;
    }

    public static void exportCollection(File exportFile, IssueCollection collection) {
        try {
            IssueCollectionParser.writeIssuesFile(exportFile, collection);
        } catch (IOException e) {
            Logger.log(String.format("Failed to export collection: %s", e));
        }
    }

    public static void addIssueToCollection(IssueCollection collection, Issue issue) {
        collection.addIssue(issue);
        writeChanges(collection);
    }

    public static void removeIssueFromCollection(IssueCollection collection, Issue issue) {
        collection.removeIssue(issue.getName());
        writeChanges(collection);
    }

    public static boolean updateIssue(IssueCollection collection,
                                      Issue issue,
                                      String name,
                                      String regex,
                                      String detail,
                                      String severity,
                                      String remediation) {
        if (collection.updateIssue(issue, name, regex, detail, severity, remediation)) {
            writeChanges(collection);
            return true;
        }
        return false;
    }

    public static void writeChanges(IssueCollection collection) {
        File collectionFile = new File(collection.getFilePath());
        exportCollection(collectionFile, collection);
    }

    // Load collections if there was a stored String of file names
    private static void loadCollections() {
        // Load collections if we saved any
        String serializedJson = callbacks.loadExtensionSetting(collectionStoreSettingName);
        JsonParser parser = new JsonParser();
        JsonArray list;
        try {
            list = parser.parse(serializedJson).getAsJsonArray();
        } catch (Exception e) {
            Logger.log("JSON stored in extension setting was invalid.");
            return;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            JsonObject object = (JsonObject) it.next();
            addCollection(new File(object.get("filePath").getAsString()),
                    Boolean.parseBoolean(object.get("inUse").getAsString()));
        }
    }

    public static void removeCollection(String fileLocation) {
        collections.remove(fileLocation);

        // Update our store setting
        storeCollectionPaths();
    }

    public static String serialize() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(new IssueCollectionStore());
        } catch (IOException e) {
            Logger.log("Failed to serialize IssueCollectionStore: " + e);
            return "[]";
        }
    }

    // Store the file paths for each collection file so we can reload them
    public static void storeCollectionPaths() {
        callbacks.saveExtensionSetting(collectionStoreSettingName, serialize());
    }
}

class IssueCollectionStoreSerializer extends StdSerializer<IssueCollectionStore> {

    public IssueCollectionStoreSerializer() {
        this(null);
    }

    public IssueCollectionStoreSerializer(Class<IssueCollectionStore> t) {
        super(t);
    }

    @Override
    public void serialize(IssueCollectionStore issueCollectionStore,
                          JsonGenerator jsonGenerator,
                          SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartArray();
        for (IssueCollection collection: IssueCollectionStore.getCollections()) {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeStringField("filePath", collection.getFilePath());
            jsonGenerator.writeStringField("inUse", Boolean.toString(collection.isInUse()));
            jsonGenerator.writeEndObject();
        }
        jsonGenerator.writeEndArray();
    }
}
