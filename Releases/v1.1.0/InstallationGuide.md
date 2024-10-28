## Installation Guide
### Prerequisite
To install **V1.1.0** release, Docker Image for dependent libraries is **required**.
1. Build a publicly accessible Docker Image for the dependencies in Docker Hub using **Docker/Dockerfile**.

2. Update the yaml file with the location of the Docker Image:
Get the Docker Image name from Docker hub where publicly accessible docker image is stored and put it in the **dockerimage** field in **Fortinet_FortiNDR_Cloud.yml**.

### Install
1. Login into Cortex XSOAR via web browser.
2. Navigate to **Settings** > **Integrations** > **Instances**.
3. Click on the **Upload** button on the top right to upload the yaml file included in the package.
4. After upload, click on **Save Version**.
5. If prompted, click on **Update Version**
6. In the search box, search for Fortinet FortiNDR Cloud , the integration would show up in the **NetWork Security** list.
7. Click on **Add Instance** one the right side of the Fortinet FortiNDR Cloud app to add a new instance.
8. Follow the Help at the right of the window to configure the instance.