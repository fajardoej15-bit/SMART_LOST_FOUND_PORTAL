# Smart Lost & Found Portal – Pasig City

## Project Title & Problem Statement

**Smart Lost & Found Portal – Pasig City**

A web-based lost and found management system designed to help Pasig City residents report lost and found items, search for possible matches, submit claim requests, provide ownership evidence, and communicate with authorized administrators.

The system aims to organize the lost-and-found process in a centralized platform instead of relying on manual reporting, scattered social media posts, or informal communication.

## Target Users & Stakeholder Value

* **Pasig City Residents:** Report lost or found items, browse available reports, receive notifications, submit claim requests, and communicate with administrators.
* **Item Finders / Surrenderers:** Report items they have found and provide information that can help return them to their rightful owners.
* **Administrators:** Review reports, manage registered users, evaluate claim requests and evidence, communicate with users, and manage case resolutions.
* **System Management:** Maintain organized records of lost and found reports, claims, notifications, messages, and resolved cases.

## Team Members & Assigned Roles

* **Lead Developer / System Developer:** Eduardo Fajardo Jr.

  * Leads the overall system development and implementation.
  * Develops the core Flask application and system logic.
  * Implements major system features and integrations.
  * Handles GitHub repository management and deployment coordination.
  * Oversees system functionality and technical decisions.

* **System Developer / Technical Support:** Eliniel Jose

  * Assists in developing and improving system features.
  * Helps identify and troubleshoot system bugs.
  * Assists with testing system functionality.
  * Supports the implementation and refinement of the application's user interface.
  * Coordinates with the lead developer during system development.

* **Quality Assurance / System Checker:** Fajardo Eduardo

  * Checks system functionality and user workflows.
  * Tests features to identify errors and unexpected behavior.
  * Verifies that implemented features work according to the system requirements.
  * Reports bugs and issues to the development team.
  * Assists in validating fixes before system deployment.

* **Documentation Lead:** Erica Gallogo

  * Prepares and maintains project documentation.
  * Documents system features, workflows, and requirements.
  * Assists in preparing technical and project documentation.
  * Organizes project information for presentation and submission.
  * Helps ensure that documentation accurately reflects the implemented system.

* **Documentation & Support:** Val Memita

  * Assists with project documentation and supporting materials.
  * Helps organize system information and project records.
  * Assists in preparing presentation and documentation requirements.
  * Supports the team in reviewing and organizing project outputs.
  * Coordinates with Erica Gallogo regarding documentation tasks.


## Key System Features

* User registration and login
* User profile management
* Profile picture upload
* Lost item reporting
* Found item reporting
* Lost and found item browsing
* Item information and report details
* Lost-and-found matching based on item information
* Claim request submission
* Ownership verification and evidence submission
* Administrator claim review
* Admin-to-user messaging
* User notifications
* Read/unread notification indicators
* Message read/seen status
* Admin user management
* Admin report management
* Case resolution management
* Claimant and item finder/surrenderer notifications
* Password recovery using security questions
* Responsive web interface
* Dark mode settings

## Planned Technology Stack

* **Frontend:** HTML5, CSS3, JavaScript
* **Backend:** Python, Flask
* **Database:** SQLite
* **Image Processing:** Pillow (PIL)
* **Development Environment:** Visual Studio Code
* **Version Control:** Git
* **Repository Hosting:** GitHub
* **Deployment:** Render

## Repository Structure

```text
SMART_LOST_FOUND_PORTAL/
│
├── main.py
├── database.py
├── auth_controller.py
├── lost_found.db
├── README.md
│
├── static/
│   └── style.css
│
└── templates/
    ├── admin_claim_detail.html
    ├── admin_report_detail.html
    ├── admin_user_detail.html
    ├── messages.html
    ├── notifications.html
    └── ...
```

## Repository & Branching Strategy

* **Main Branch:** `main`
* **Development Branch:** `develop`
* **Feature Branches:** `feature/`

Example feature branch:

```text
feature/message-notifications
```

## System Workflow

1. A user creates an account or logs into an existing account.
2. The user reports an item as **Lost** or **Found**.
3. The system stores the report and relevant item information.
4. Users can browse available lost-and-found reports.
5. Potential matches can be identified using available item information.
6. A user who believes an item belongs to them can submit a claim request.
7. The claimant provides ownership information or supporting evidence.
8. The administrator reviews the report, claim request, and evidence.
9. The administrator communicates with the relevant user when additional information is required.
10. If the claim is approved, the claimant receives instructions regarding where and how to claim the item.
11. The person who surrendered/found the item receives a notification when the case is resolved.
12. The administrator records the case resolution.

## Administrator Responsibilities

The administrator dashboard provides authorized administrators with tools to:

* Review lost reports
* Review found reports
* Review claim requests
* Review submitted evidence
* Manage registered users
* Communicate with users
* Monitor notifications and activities
* Resolve completed cases
* Maintain organized lost-and-found records

## Security & Verification

The system uses account authentication and administrator authorization to protect system functions.

Claim requests require users to provide identifying information or evidence before an administrator can approve the release of an item.

Administrative functions are restricted to authorized administrator accounts.

## Deployment

The application is deployed using **Render** and connected to the project's GitHub repository.

The deployment workflow is:

```text
VS Code
   ↓
Git Commit
   ↓
GitHub
   ↓
Render Auto-Deploy
   ↓
Live Web Application
```

## Project Goal

The goal of the Smart Lost & Found Portal is to provide Pasig City residents with a centralized and organized way to report, search, verify, claim, and resolve lost-and-found items through a web-based platform.
