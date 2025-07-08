### **Why This Dashboard?**

Initially, I started customizing the existing Power BI dashboard for a client. But as I dug in, it became clear that the Power BI solution was missing some key information — especially around **patch compliance**.

At the moment, I think the **patch compliance within Intune** is unreliable — and that’s a major gap in Intune Reporting. In fact, that gap is what ultimately prompted me to go “off script” and develop an alternative solution using **PowerShell** instead.

---

### **What I Built**

The custom **PowerShell-based dashboard** I created pulls together a broad range of Intune metrics:

- **Devices**
    
- **Users**
    
- **Policy compliance**
    
- **User experience scores**
    
- And most importantly: **Patch compliance**
    

---

### **Why PowerShell?**

This solution offers a few important advantages:

- **Reusable**: Just like Power BI, this dashboard can be implemented for **any client** with similar needs.
    
- **Simple setup**: It uses a **text-based configuration file** with key-value pairs to control everything.
    
- **No scripting required**: Admins won’t need to touch PowerShell code — all customization happens through the config file.

- **From dashboard to terminal**: Running the script interactively lets you continue working with the retrieved data. All data is stored in a custom PowerShell object called $managedEnvironment, allowing for further exploration beyond the dashboard.
    

---

### **What You Can Configure**

The configuration file gives you full control over the dashboard’s behavior:

- **Tenant setup**: Tenant name, ID, and auth settings
    
- **Dashboard metadata**: Title, author, display options
    
- **Auto-refresh & data refresh intervals**
    
- **Theming**: Color schemes and visual styles
    
- **Content toggles**: For example, you can turn off the _Users_ tab entirely if it’s not needed
    
- **Layout options**: Table paging, button layout, and other UI preferences
    
- **Thresholds**: For things like low disk space, patch compliance levels, etc.
    

---

### **In Summary**

This dashboard fills a critical gap for many of my clients and can be easily adapted for any environment. It provides deep visibility into Intune environments without the constraints of Power BI — and without the need for advanced scripting knowledge to maintain or deploy it.
