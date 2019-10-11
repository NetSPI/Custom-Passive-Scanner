package burp;

import customPassiveScanner.*;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.Timer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class CustomScannerTab implements ITab
{
    final String tabName = "Custom Passive Scanner";
    final String[] severities = {"Information", "Low", "Medium","High"};
    IssueCollection currentParent;
    Issue currentlyEditing;
    JSplitPane splitPane;
    JPanel treePanel;
    DefaultMutableTreeNode rootNode;
    JTree collectionsTree;
    JPanel rightPanel;
    JTextField nameField;
    JTextField regexField;
    JTextArea detailsArea;
    JComboBox severityMenu;
    JTextArea remediationArea;
    boolean cancelNextUpdate;
    UpdateTimer updateTimer;

    public CustomScannerTab(IBurpExtenderCallbacks callbacks) {

        this.splitPane = new JSplitPane();
        this.splitPane.setDividerLocation(250);

        this.splitPane.setLeftComponent(buildLeftPanel());
        this.splitPane.setRightComponent(buildRightPanel());

        updateTimer = new UpdateTimer();

        callbacks.addSuiteTab(this);
    }

    // Create the left panel of the Burp tab
    private JPanel buildLeftPanel() {
        JPanel leftPanel = new JPanel(new GridBagLayout());
        leftPanel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weighty = 0;
        constraints.weightx = 0;
        constraints.fill = GridBagConstraints.NONE;

        JLabel collectionsLabel = new JLabel("Collections");
        Font labelFont = collectionsLabel.getFont();
        collectionsLabel.setFont(labelFont.deriveFont(labelFont.getStyle() | Font.BOLD));
        leftPanel.add(collectionsLabel, constraints);


        // Create tree panel
        this.treePanel = new JPanel(new GridLayout(0,1));

        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.weighty = 1;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.BOTH;
        leftPanel.add(this.treePanel, constraints);


        this.populateTree(treePanel);


        // Create button panel
        JPanel buttonPanel = new JPanel(new GridBagLayout());

        // Add enable button to panel
        JButton enableButton = new JButton("Enable Collections");
        enableButton.addActionListener(e -> setInUseStateOfSelections(true));
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weightx = .5;
        constraints.weighty = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        buttonPanel.add(enableButton, constraints);

        // Add disable button to panel
        JButton disableButton = new JButton("Disable Collections");
        disableButton.addActionListener(e -> setInUseStateOfSelections(false));
        constraints.gridx = 1;
        buttonPanel.add(disableButton, constraints);

        // Add import button to panel
        JButton importButton = new JButton("Import");
        importButton.addActionListener(e -> importCollection());
        constraints.gridx = 0;
        constraints.gridy += 1;
        constraints.weightx = .5;
        constraints.weighty = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        buttonPanel.add(importButton, constraints);

        // Add export button to panel
        JButton exportButton = new JButton("Export");
        exportButton.addActionListener(e -> exportCollections());
        constraints.gridx = 1;
        buttonPanel.add(exportButton, constraints);

        // Add "remove collection" button to panel
        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> remove());
        constraints.gridx = 0;
        constraints.gridy += 1;
        buttonPanel.add(removeButton, constraints);

        // Add "Add issue" button to panel
        JButton addIssueButton = new JButton("Add Issue");
        addIssueButton.addActionListener(e -> addIssue());
        constraints.gridx = 1;
        buttonPanel.add(addIssueButton, constraints);

        constraints.gridx = 0;
        constraints.gridy += 1;
        constraints.weighty = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        leftPanel.add(buttonPanel, constraints);
        return leftPanel;
    }

    private JPanel buildRightPanel() {
        this.rightPanel = new JPanel(new GridBagLayout());
        this.rightPanel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
        GridBagConstraints constraints = new GridBagConstraints();

        // Add all labels
        JLabel nameLabel = new JLabel("Issue Name: ");
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.insets = new Insets(5,5,5,5);
        constraints.anchor = GridBagConstraints.FIRST_LINE_START;
        this.rightPanel.add(nameLabel, constraints);

        JLabel regexLabel = new JLabel("Regex: ");
        constraints.gridy = constraints.gridy + 1;
        this.rightPanel.add(regexLabel, constraints);

        JLabel detailsLabel = new JLabel("Issue Details: ");
        constraints.gridy = constraints.gridy + 1;
        this.rightPanel.add(detailsLabel, constraints);

        JLabel severityLabel = new JLabel("Severity: ");
        constraints.gridy = constraints.gridy + 1;
        this.rightPanel.add(severityLabel, constraints);

        JLabel remediationLabel = new JLabel("Remediation: ");
        constraints.gridy = constraints.gridy + 1;
        constraints.weighty = 1;
        this.rightPanel.add(remediationLabel, constraints);

        // Add all input fields
        this.nameField = new JTextField();
        constraints.gridx = 1;
        constraints.gridy = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1;
        constraints.weighty = 0;
        this.nameField.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {
            }

            @Override
            public void keyPressed(KeyEvent e) {

            }

            @Override
            public void keyReleased(KeyEvent e) {
                updateTimer.schedule();
            }
        });
        this.rightPanel.add(this.nameField, constraints);

        this.regexField = new JTextField();
        constraints.gridy = constraints.gridy + 1;
        this.regexField.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {
            }

            @Override
            public void keyPressed(KeyEvent e) {

            }

            @Override
            public void keyReleased(KeyEvent e) {
                updateTimer.schedule();
            }
        });
        this.rightPanel.add(regexField, constraints);

        this.detailsArea = new JTextArea();
        detailsArea .setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, null);
        detailsArea .setLineWrap(true);
        JScrollPane detailsScrollPane = new JScrollPane();
        detailsScrollPane.setViewportView(detailsArea );
        detailsScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        detailsScrollPane.setPreferredSize(new Dimension(300,100));
        constraints.gridy = constraints.gridy + 1;
        this.detailsArea.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {

            }

            @Override
            public void keyPressed(KeyEvent e) {

            }

            @Override
            public void keyReleased(KeyEvent e) {
                updateTimer.schedule();
            }
        });
        this.rightPanel.add(detailsScrollPane, constraints);


        this.severityMenu = new JComboBox(this.severities);
        severityMenu.setSelectedIndex(0);
        constraints.gridy = constraints.gridy + 1;
        constraints.weighty = 0;
        this.severityMenu.addActionListener(e -> {
            updateTimer.schedule();
        });
        this.rightPanel.add(severityMenu, constraints);


        this.remediationArea = new JTextArea();
        remediationArea.setLineWrap(true);
        remediationArea.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, null);
        JScrollPane remediationScrollPane = new JScrollPane();
        remediationScrollPane.setViewportView(remediationArea);
        remediationScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        remediationScrollPane.setPreferredSize(new Dimension(300,100));
        constraints.gridy = constraints.gridy + 1;
        this.remediationArea.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {
            }

            @Override
            public void keyPressed(KeyEvent e) {

            }

            @Override
            public void keyReleased(KeyEvent e) {
                updateTimer.schedule();
            }
        });
        this.rightPanel.add(remediationScrollPane, constraints);

        return this.rightPanel;
    }


    private void reloadTree(DefaultMutableTreeNode node) {
        ((DefaultTreeModel) this.collectionsTree.getModel()).reload(node);
    }

    private void populateIssueDetails() {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) this.collectionsTree.getLastSelectedPathComponent();
        if (node.getUserObject() instanceof Issue) {
            this.currentlyEditing = (Issue) node.getUserObject();
            this.currentParent = (IssueCollection) ((DefaultMutableTreeNode) node.getParent()).getUserObject();

            this.nameField.setText(this.currentlyEditing.getName());
            this.regexField.setText(this.currentlyEditing.getRegex());
            this.detailsArea.setText(this.currentlyEditing.getDetail());
            int sevIndex = Arrays.asList(this.severities).indexOf(this.currentlyEditing.getSeverity());
            this.remediationArea.setText(this.currentlyEditing.getRemediation());

            // Update this field last, because it triggers an update to the Issue
            if (sevIndex >= 0) {
                cancelNextUpdate = true;
                this.severityMenu.setSelectedIndex(sevIndex);
            } else {
                Logger.log(String.format("Issue %s does not contain proper severity.", this.currentlyEditing.getName()));
                this.severityMenu.setSelectedIndex(0);
            }
        }
    }

    private void clearIssueDetails() {
        this.currentlyEditing = null;
        this.currentParent = null;
        this.nameField.setText("");
        this.regexField.setText("");
        this.detailsArea.setText("");
        this.severityMenu.setSelectedIndex(0);
        this.remediationArea.setText("");

    }

    private boolean isNodeEnabled(DefaultMutableTreeNode node) {
        Object userObject = node.getUserObject();
        if (userObject instanceof IssueCollection) {
            return ((IssueCollection) userObject).isInUse();
        } else {
            // Get the parent collection to determine if the node is enabled
            Object parentObject = ((DefaultMutableTreeNode) node.getParent()).getUserObject();
            return ((IssueCollection) parentObject).isInUse();
        }
    }

    private void populateTree(JPanel treePanel) {

        this.rootNode = new DefaultMutableTreeNode();
        this.collectionsTree = new JTree(rootNode);
        this.collectionsTree.setCellRenderer(new DefaultTreeCellRenderer() {
            @Override
            public Component getTreeCellRendererComponent(JTree tree,
                                                 Object value,
                                                 boolean sel,
                                                 boolean expanded,
                                                 boolean leaf,
                                                 int row,
                                                 boolean hasFocus) {
                Object userObject = ((DefaultMutableTreeNode) value).getUserObject();
                String nodeText;
                if (userObject instanceof IssueCollection || userObject instanceof Issue) {
                    if (isNodeEnabled((DefaultMutableTreeNode) value)) {
                        nodeText = String.format("<html><p>%s</p></html>", userObject.toString());
                    } else {
                        nodeText = String.format("<html><font color=gray><p>%s</p></font></html>", userObject.toString());
                    }
                    return super.getTreeCellRendererComponent(tree, nodeText, sel, expanded, leaf, row, hasFocus);
                } else {
                    return super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
                }
            }
        });
        this.collectionsTree.setRootVisible(false);
        this.collectionsTree.addTreeSelectionListener(e -> {
            if (e.getNewLeadSelectionPath() != null) {
                populateIssueDetails();
            }
        });
        for (IssueCollection collection : IssueCollectionStore.getCollections()) {
            addCollectionToTree(collection);
        }

        treePanel.add(this.collectionsTree);
        reloadTree(this.rootNode);
    }

    private void addCollectionToTree(IssueCollection collection) {
        DefaultMutableTreeNode collectionNode = new DefaultMutableTreeNode(collection);

        // Iterate over all issues in collection, and add them to the tree
        Iterator it = collection.getIssues().entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Issue> pair = (Map.Entry) it.next();
            DefaultMutableTreeNode issueNode = new DefaultMutableTreeNode(pair.getValue());
            collectionNode.add(issueNode);
        }

        this.rootNode.add(collectionNode);
    }

    private void updateIssue() {

        if (this.currentlyEditing == null) {
            // This is in case an update is triggered by our reset of the severity menu
            return;
        }

        boolean updateSuccessful = IssueCollectionStore.updateIssue(this.currentParent,
                this.currentlyEditing,
                this.nameField.getText(),
                this.regexField.getText(),
                this.detailsArea.getText(),
                (String) this.severityMenu.getSelectedItem(),
                this.remediationArea.getText());

        if (!updateSuccessful) {
            // Name is the only field right now that should cause failure, just remove that update
            this.nameField.setText(this.currentlyEditing.getName());
        }
    }

    private void setInUseStateOfSelections(boolean enabled) {
        boolean selectedCollection = false;
        TreePath[] selectionPaths = this.collectionsTree.getSelectionPaths();
        if (selectionPaths != null) {
            for (TreePath path : selectionPaths) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                Object userObject = node.getUserObject();
                if (userObject instanceof IssueCollection) {
                    selectedCollection = true;
                    ((IssueCollection) userObject).setInUse(enabled);
                    DefaultTreeModel model = (DefaultTreeModel) this.collectionsTree.getModel();
                    model.nodeChanged(node);

                    // Make sure we change all the children too
                    Enumeration children = node.children();
                    while (children.hasMoreElements()) {
                        DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) children.nextElement();
                        this.reloadTree(childNode);
                    }
                }
            }
        }

        if (!selectedCollection && enabled) {
            new ErrorPopup("Please select at least one collection to enable");
        } else if (!selectedCollection && !enabled) {
            new ErrorPopup("Please select at least one collection to disable");
        }
    }

    private void recursiveLoadCollections(File file) {
        if (!file.isDirectory()) {
            IssueCollection collection = IssueCollectionStore.addCollection(file);
            if (collection != null) {
                addCollectionToTree(collection);
            }
        } else {
            for (File child : file.listFiles()) {
                recursiveLoadCollections(child);
            }
        }
    }

    private void importCollection() {
        // Import a collection file from a local file
        // Open file chooser
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        int dialogueResult = fileChooser.showOpenDialog(this.getBurpFrame());
        if (dialogueResult == JFileChooser.APPROVE_OPTION) {

            // Iterate over selected files
            File[] files = fileChooser.getSelectedFiles();
            for (File file : files) {
                this.recursiveLoadCollections(file);
            }
        }

        reloadTree(this.rootNode);
    }

    private void exportCollectionsAsZip(TreePath[] selectionPaths) {
        // Select destination for zip file
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select location to save collection");
        int dialogeResult = fileChooser.showSaveDialog(this.getBurpFrame());
        if (dialogeResult == JFileChooser.APPROVE_OPTION) {
            ZipOutputStream zipFile;
            try {
                zipFile = new ZipOutputStream(new FileOutputStream(fileChooser.getSelectedFile()));
            } catch (IOException e) {
                Logger.log("Failed to open zip file for writing");
                return;
            }

            for (TreePath selection : selectionPaths) {
                Object lastNodeObject = ((DefaultMutableTreeNode) selection.getLastPathComponent()).getUserObject();
                IssueCollection collection = (IssueCollection) lastNodeObject;
                try {
                    // Create and write to temp file
                    File tmpFile = File.createTempFile(collection.getName(), ".yaml");
                    FileInputStream tmpStream = new FileInputStream(tmpFile);
                    IssueCollectionStore.exportCollection(tmpFile, collection);

                    // Add temp file to zip
                    ZipEntry collectionEntry = new ZipEntry(collection.getName() + ".yaml");
                    zipFile.putNextEntry(collectionEntry);
                    byte[] bytes = new byte[1024];
                    int length;
                    while ((length = tmpStream.read(bytes)) >= 0) {
                        zipFile.write(bytes,0, length);
                    }

                    // Close temp file
                    zipFile.closeEntry();
                    tmpFile.delete();
                } catch (IOException e) {
                    Logger.log(String.format("Failed to write %s to file for zip", collection.getName()));
                    continue;
                }
            }

            try {
                zipFile.close();
            } catch (IOException e) {
                Logger.log("Failed to close zip file");
            }
        }
    }

    private void exportSingleCollection(TreePath selectionPath) {
        // Get
        Object lastNodeObject = ((DefaultMutableTreeNode) selectionPath.getLastPathComponent()).getUserObject();
        IssueCollection collection = (IssueCollection) lastNodeObject;
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select location to save collection");

        int dialogResult = fileChooser.showSaveDialog(this.getBurpFrame());
        if (dialogResult == JFileChooser.APPROVE_OPTION) {
            File exportFile = fileChooser.getSelectedFile();
            IssueCollectionStore.exportCollection(exportFile, collection);
        }
    }

    // Check all selection paths to see if any are not Collections
    private boolean selectionContainsOnlyCollections(TreePath[] selections) {
        for (TreePath selection : selections) {
            Object lastNodeObject = ((DefaultMutableTreeNode) selection.getLastPathComponent()).getUserObject();
            if (!(lastNodeObject instanceof IssueCollection)) {
                return false;
            }
        }
        return true;
    }

    private void exportCollections() {
        TreePath[] selectionPaths = this.collectionsTree.getSelectionPaths();
        if (selectionPaths != null) {
            if (selectionContainsOnlyCollections(selectionPaths)) {
                if (selectionPaths.length == 1) {
                    exportSingleCollection(selectionPaths[0]);
                } else {
                    exportCollectionsAsZip(selectionPaths);
                }
            } else {
                new ErrorPopup("Please only select collections for export");
            }
        } else {
            new ErrorPopup("Please select at least one collection to export");
        }
    }

    private void remove() {
        // Clear the current issue if there is one. This makes the update operation a simpler task
        clearIssueDetails();

        TreePath[] paths = this.collectionsTree.getSelectionPaths();
        if (paths == null) {
            new ErrorPopup("Please select at least one collection or issue to remove");
            return;
        }
        DefaultTreeModel treeModel = (DefaultTreeModel) this.collectionsTree.getModel();

        // Remove everything that was selected
        for (TreePath path : paths) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object userObject = node.getUserObject();
            if (userObject instanceof IssueCollection) {
                // If a collection is selected, just remove it from the store
                IssueCollectionStore.removeCollection(((IssueCollection) userObject).getFilePath());
            } else {
                // If an issue is selected, remove it from the collection
                IssueCollection collection = (IssueCollection) ((DefaultMutableTreeNode) node.getParent()).getUserObject();
                IssueCollectionStore.removeIssueFromCollection(collection, (Issue) userObject);
            }
            treeModel.removeNodeFromParent(node);
        }
    }

    private void addIssue() {
        DefaultMutableTreeNode collectionNode = (DefaultMutableTreeNode) this.collectionsTree.getLastSelectedPathComponent();
        if (collectionNode == null) {
            new ErrorPopup("Please select a collection to create a new issue in");
            return;
        }
        Object userObject = collectionNode.getUserObject();
        if (userObject instanceof IssueCollection) {
            // Clear UI
            clearIssueDetails();
            this.nameField.setText("New Issue");

            // Create new issue
            Issue issue = new Issue();
            issue.setName("New Issue");
            issue.setRegex("");
            issue.setDetail("");
            issue.setSeverity("Information");
            issue.setRemediation("");
            IssueCollectionStore.addIssueToCollection(((IssueCollection) userObject), issue);

            // Create new tree node
            DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(issue);
            collectionNode.add(newNode);
            this.currentlyEditing = issue;
            this.currentParent = (IssueCollection) userObject;

            this.reloadTree(collectionNode);
            this.collectionsTree.setSelectionPath(new TreePath(newNode.getPath()));
        } else {
            new ErrorPopup("Please select a collection before creating a new issue.");
        }
    }

    public static Frame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return f;
            }
        }
        return null;
    }

    @Override
    public String getTabCaption() {
        return tabName;
    }

    @Override
    public Component getUiComponent() {
        return this.splitPane;
    }

    // These shenanigans are here so we don't fire an update every single time someone types a thing.
    // Probably could delay further, but name was the biggest issue, and that should be fairly short
    class UpdateTimer extends Timer {
        private UpdateTask updateTask;
        private boolean isScheduled = false;
        private final long delay = 1000;

        public void schedule() {
            // Used in case we trigger an update by manually changing fields
            if (cancelNextUpdate) {
                cancelNextUpdate = false;
                return;
            }

            if (!isScheduled) {
                isScheduled = true;
            } else {
                updateTask.cancel();
            }

            updateTask = new UpdateTask();
            super.schedule(updateTask, delay);
        }

        public void cancel() {
            if (isScheduled) {
                isScheduled = false;
                updateTask.cancel();
            }
        }

        class UpdateTask extends TimerTask {
            public void run() {
                isScheduled = false;
                updateIssue();
            }
        }
    }
}
