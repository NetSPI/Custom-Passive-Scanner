package customPassiveScanner;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TimerTask;


public class IssueCollection {
    private String name;
    private String filePath;
    private boolean inUse = true;
    private Map<String, Issue> issues;

    public boolean isInUse() {
        return inUse;
    }

    public void setInUse(boolean inUse) {
        this.inUse = inUse;
    }

    public String getFilePath() {
        return filePath;
    }

    public boolean containsIssue(String issueName) {
        return this.issues.containsKey(issueName);
    }

    public Map<String, Issue> getIssues() {
        return this.issues;
    }

    public void setIssues(Map<String, Map<String, String>> newIssues) {
        this.issues = new HashMap<String, Issue>();

        // Loop over all of our issue definitions
        Iterator it = newIssues.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Map<String, String>> pair = (Map.Entry) it.next();
            Issue newIssue = Issue.createIssue(pair.getKey(), pair.getValue());

            // If we successfully found a new issue, add it
            if (newIssue != null) {
                this.issues.put(newIssue.getName(), newIssue);
            }
        }
    }


    public void addIssue(Issue issue) {
        if (issues.containsKey(issue.getName())) {
            Logger.log(String.format("Failed to add issue to collection. Issue name %s already exists.", issue.getName()));
        } else {
            issues.put(issue.getName(), issue);
        }
    }

    public void removeIssue(String issueName) {
        if (issues.containsKey(issueName)) {
            issues.remove(issueName);
        }
    }

    public boolean updateIssue(Issue issue,
                              String name,
                              String regex,
                              String detail,
                              String severity,
                              String remediation) {
        // Update all fields before name, because we may fail there
        issue.setRegex(regex);
        issue.setDetail(detail);
        issue.setSeverity(severity);
        issue.setRemediation(remediation);

        // Now try to update name
        if (!issue.getName().equals(name)) {
            // If updating the name, we need to know if it exists already
            if (issues.containsKey(name)) {
                new ErrorPopup("An issue with this name already exists in the collection.");
                return false;
            }  else {
                issues.remove(issue.getName());
                issue.setName(name);
                issues.put(name, issue);
            }
        }

        return true;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String toString() {
        return this.getName();
    }
}
