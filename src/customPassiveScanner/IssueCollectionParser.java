package customPassiveScanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.*;

public class IssueCollectionParser {

    // Parse new issues
    public static IssueCollection parseIssuesFile(File newCollectionFile) throws IOException {
        // Parse YAML doc
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        IssueCollection collection = mapper.readValue(new File(newCollectionFile.getPath()), IssueCollection.class);
        collection.setFilePath(newCollectionFile.getAbsolutePath());
        return collection;
    }

    public static void writeIssuesFile(File exportFile, IssueCollection collection) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        mapper.writeValue(exportFile, collection);
    }
}
