# Governance & Regulation
> https://tryhackme.com/room/cybergovernanceregulation

 Information Security Frameworks
The information security framework provides a comprehensive set of documents that outline the organisation's approach to information security and governs how security is implemented, managed, and enforced within the organisation. This mainly includes:
- Policies: A formal statement that outlines an organisation's goals, principles, and guidelines for achieving specific objectives.
- Standards: A document establishing specific requirements or specifications for a particular process, product, or service.
- Guidelines: A document that provides recommendations and best practices (non-mandatory) for achieving specific goals or objectives.
- Procedures: Set of specific steps for undertaking a particular task or process.
- Baselines: A set of minimum security standards or requirements that an organisation or system must meet.

**Developing Governance Documents**
![governance](media/29-governance.png)
Define Purpose:

Clearly outline what the document will cover and why it's necessary. For instance, a password policy ensures strong user passwords, while a baseline sets a minimum security level for systems.
Research:

Investigate laws, regulations, industry standards, and best practices for a comprehensive and current document. Check existing documents to avoid duplication or contradictions.
Drafting:

Develop a clear and concise outline. Draft the document with specificity, ensuring it aligns with organizational goals and values. Follow best practices for different document types.
Review and Approval:

Have the document reviewed by stakeholders, including experts and legal teams. Incorporate feedback, ensuring alignment with organizational goals. Secure final approval from relevant stakeholders.
Implementation and Communication:

Communicate the document to all involved parties. Ensure understanding of roles and responsibilities in implementing it. Develop training programs for clarity and adherence.
Review and Update:

Regularly review and update the document to keep it relevant. Monitor compliance, adjusting based on feedback and changes in the threat landscape or regulations.

**Preparing a Password Policy**
- Define password requirements: Minimum length, complexity, and expiration.
- Define password usage guidelines: Specify how passwords should be used, such as requiring unique passwords for each account, prohibiting the sharing of passwords, and prohibiting default passwords.
- Define password storage and transmission guidelines: Using encryption for password storage and requiring secure connections for password transmission.
- Define password change and reset guidelines: How often passwords should be changed etc. 
- Communicate the policy: Communicate the password policy to all relevant employees and stakeholders, and ensure that they understand the requirements and guidelines. Develop training and awareness programs to ensure that employees follow the policy.
- Monitor compliance: Monitor compliance with the password policy and adjust the policy as needed based on feedback and changes in the threat landscape or regulatory environment.

**Making an Incident Response Procedure**
- Define incident types: Unauthorised access, malware infections, or data breaches.
- Define incident response roles and responsibilities: Identify the stakeholders,  such as incident response team members, IT personnel, legal and compliance teams, and senior management. 
- Detailed Steps: Develop step-by-step procedures for responding to each type of incident,  including initial response steps, such as containing the incident and preserving evidence; analysis and investigation steps, such as identifying the root cause and assessing the impact; response and recovery steps, such as mitigating the incident, reporting and restoring normal operations.
- Report the incident to management and document the incident response process for future reference.
- Communicate the incident response procedures.
- Review and update the incident response procedures.


## Governance Risk and Compliance (GRC)
![grc](media/29-grc.png)

As we have studied, information security governance and compliance are necessary to maintain any organisation's overall security posture. But how to achieve it? Here comes the role of the Governance and Risk Compliance (GRC) framework. It focuses on steering the organisation's overall governance, enterprise risk management, and compliance in an integrated manner. It is a holistic approach to information security that aligns with the organisation's goals and objectives and helps to ensure that the organisation operates within the boundaries of relevant regulations and industry standards. GRC framework has the following three components:

Components of GRC
- Governance Component: Involves guiding an organisation by setting its direction through information security strategy,  which includes policies, standards, baselines, frameworks, etc., along with establishing appropriate monitoring methods to measure its performance and assess the outcomes.
- Risk Management Component: Involves identifying, assessing, and prioritising risks to the organisation and implementing controls and mitigation strategies to manage those risks effectively. This includes monitoring and reporting on risks and continuously evaluating and refining the risk management program to ensure its ongoing effectiveness.
- Compliance Component: Ensuring that the organisation meets its legal, regulatory, and industry obligations and that its activities align with its policies and procedures. This includes developing and implementing compliance programs, conducting regular audits and assessments, and reporting on compliance issues to stakeholders.

**How to Develop GRC Program - Generic Guidelines** 
A well-developed and implemented GRC program for cyber security provides an integrated framework for managing risks, complying with regulations and standards, and improving the overall security perspective of an organisation. It enables effective governance, risk management, and compliance activities, mitigating cyber incidents' impact and ensuring business resilience. In this section, we will explore how to develop and implement a GRC framework. Developing and implementing a GRC framework involves various steps; we will explain each step with an appropriate example so that we can easily understand:

- Define the scope and objectives: This step involves determining the scope of the GRC program and defining its goals. For example, a company can implement a GRC program for its customer data management system. The objective might be to reduce cyber risks to 50% in the next 12 months while maintaining the trust of its customers. 
- Conduct a risk assessment: In this step, the organisation identifies and assesses its cyber risks. For example, a risk assessment might reveal that the customer data management system is vulnerable to external attacks due to weak access controls or outdated software. The organisation can then prioritize these risks and develop a risk management strategy.
- Develop policies and procedures: Policies and procedures are developed to guide cyber security practices within the organisation. For example, the company might establish a password policy to ensure the usage of strong passwords. They might also implement logging and monitoring system access procedures to detect suspicious activity.
- Establish governance processes: Governance processes ensure the GRC program is effectively managed and controlled. For example, the organisation might establish a security steering committee that meets regularly to review security risks and make decisions about security investments and priorities. Roles and responsibilities are defined to ensure everyone understands their role in the program.
- Implement controls: Technical and non-technical controls are implemented to mitigate risks identified in risk assessment. For example, the company might implement firewalls, Intrusion Prevention System (IPS), Intrusion Detection System (IDS), and Security Information and Event Management (SIEM) to prevent external attacks and impart employee training to improve security awareness and reduce the risk of human error.
- Monitor and measure performance: Processes are established to monitor and measure the effectiveness of the GRC program. For example, the organisation can track metrics and compliance with security policies. This information is used to identify areas for improvement and adjust the program as needed.
- Continuously improve: The GRC program is constantly reviewed and improved based on performance metrics, changing risk profiles, and stakeholder feedback. For example, suppose the organisation experiences a security incident. In that case, it might conduct a post-incident analysis to identify the root cause and make changes to prevent a similar incident from happening again.


Related Rooms:
- Intrusion Detection: https://tryhackme.com/room/idsevasion
- IDS/IPS evasion techniques: https://tryhackme.com/room/redteamnetsec
- SIEM: https://tryhackme.com/room/introtosiem

## Privacy and Data Protection
General Data Protection Regulation (GDPR)
The GDPR is a data protection law implemented by the EU in May 2018 to protect personal data. Personal data is "Any data associated with an individual that can be utilised to identify them either directly or indirectly". Key points of the law include the following:

- Prior approval must be obtained before collecting any personal data.
- Personal data should be kept to a minimum and only collected when necessary.
- Adequate measures are to be adopted to protect stored personal data.
![gdpr](media/29-gdpr.png)

The law applies to all business entities that conduct business in the European Union (EU) and collect/store/process the personal data of EU residents and are required to comply. It is one of the most stringent data privacy regulations worldwide and safeguards personal data during collection. Companies can only collect personal data for a legitimate reason and must inform the owner about its processing. Moreover, this also includes penalties and fines based on non-compliance in the following two tiers:

- Tier 1: More severe violations, including unintended data collection, sharing data with third parties without consent, etc. Maximum penalty amounting to 4% of the organisation's revenue or 20 million euros (whichever is higher).
- Tier 2: Less severe violations, including data breach notifications, cyber policies, etc. The maximum fine for Tier 2 is 2% of the organisation's revenue or 10 million euros (whichever is higher).

**Payment Card Industry Data Security Standard (PCI DSS)**
PCI DSS is focused on maintaining secure card transactions and protecting against data theft and fraud. It is widely used by businesses, primarily online, for card-based transactions. It was established by major credit card brands (Visa, MasterCard & American Express). It requires strict control access to cardholder information and monitoring unauthorised access, using recommended measures such as web application firewalls and encryption. You can learn more about the standard here.
> https://www.pcisecuritystandards.org/


Related Links:
- General Data Protection Regulation: https://gdpr-info.eu/

## NIST Special Publications
NIST 800-53 is a publication titled "Security and Privacy Controls for Information Systems and Organisations",  developed by the National Institute of Standards and Technology (NIST), US, that provides a catalogue of security controls to protect the CIA triad of information systems. The publication serves as a framework for organisations to assess and enhance the security and privacy of their information systems and comply with various laws, regulations, and policies. It incorporates best practices from multiple sources, including industry standards, guidelines, and international frameworks.
> https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf

**Key Points**
NIST 800-53 offers a comprehensive set of security and privacy controls that organisations can use to safeguard their operations, assets, personnel, and other organisations from various threats and risks. These include intentional attacks, unintentional errors, natural disasters, infrastructure failures, foreign intelligence activity, and privacy concerns. NIST 800-53 Revision 5 organises security controls into twenty families, each addressing a specific security concern category. You can learn more about the controls here (Section 2.2).

![nist-keypoints](media/29-nist.png)

**Compliance Best Practices**
First and foremost, businesses must conduct a thorough discovery process to recognise and catalogue their data assets, information systems, and associated threats. This includes understanding data flows, system dependencies, and potential vulnerabilities. What are some of best NIST 800-53 compliance practicesThe NIST 800-53 control families must be mapped to the identified assets and hazards, making creating a structured approach for matching the controls to the organisation's demands easier. Thirdly, creating a governance structure, allocating duties, and outlining precise controls implementation and maintenance procedures are all necessary to effectively manage the implementation process. All measures must be regularly monitored and evaluated to ensure compliance. Finally, organisations should establish effective monitoring systems to identify and address security issues, conduct routine evaluations and audits, and improve control implementation. By adhering to these best practices, organisations can successfully implement NIST 800-53 and enhance their security outlook while mitigating risks effectively.

![nist-compliance](media/29-nist-compliance.png)

**NIST 800-63B**
NIST Special Publication 800-63B is a set of guidelines created by the NIST to help organisations establish effective digital identity practices. Its primary focus is on authenticating and verifying the identities of individuals who access digital services, systems, and networks. The guidelines provide recommendations for different levels of identity assurance, ranging from basic to high assurance. They also offer advice on using authentication factors, including passwords, biometrics, and tokens, and securely managing and storing user credentials.

## Information Security Managemnt and Compliance
The strategic planning, execution, and continuous administration of security measures are all part of Information Security (IS) management, which protects information assets from unauthorised access, use, disclosure, interruption, alteration, and destruction. It involves risk assessment and identification, security controls and procedures development, incident response planning, and security awareness training. Contrarily, compliance refers to observing information security-related legal, regulatory, contractual, and industry-specific standards. In IS management and compliance, we will go through two key standards.

**ISO/IEC 27001**

ISO 27001 is an internationally recognised standard for requirements to plan, develop, run, and update an organisation's Information Security Management System (ISMS). The official ISO/IEC 27001 documents are paid for and can be purchased from this link. It was developed by International Organization for Standardization (ISO) and the International Electrotechnical Commission (IEC) and has the following core components:

- Scope: This specifies the ISMS's boundaries, including the covered assets and processes.
- Information security policy: A high-level document defining an organisation's information security approach.
- Risk assessment: Involves identifying and evaluating the risks to the confidentiality, integrity, and availability of the organisation's information.
- Risk treatment: Involves selecting and implementing controls to reduce the identified risks to an acceptable level.
- Statement of Applicability (SoA): This document specifies which controls from the standard are applicable and which are not.
- Internal audit: This involves conducting periodic audits of the ISMS to ensure that it is operating effectively.
- Management review: Review the performance of ISMS at regular intervals.

![iso](media/29-iso.png)

An ISMS built on the ISO 27001 standard requires careful design and execution. It entails exhaustively evaluating the organisation's security procedures, detecting gaps, and conducting a thorough risk assessment. Access control, incident response, etc., are just a few examples of the areas where clear rules and processes must be created and aligned with ISO 27001 requirements. Leadership support and resource allocation are also essential for the ISMS to be implemented successfully. Regular monitoring, measurement, and continual development are crucial to guarantee the efficacy and continued alignment of the ISMS with the organization's objectives.

**Service Organisation Control 2 (SOC 2)**
SOC 2 was developed by the American Institute of Certified Public Accountants (AICPA) as a compliance/auditing framework. It focuses on assessing the efficacy of a company's data security based on the CIA triad. SOC 2 can reassure customers, stakeholders, and business partners that the company has put sufficient controls in place to safeguard its systems, data, and sensitive information.

The SOC 2 framework is essential for service providers interacting with client data or offering solutions that process, store, or transmit sensitive data. It assists businesses in demonstrating their dedication to upholding strict privacy and security standards. Customers frequently ask for SOC 2 reports or use them as a competitive advantage to guarantee clients that their information will be handled securely. You can learn more about it here.
