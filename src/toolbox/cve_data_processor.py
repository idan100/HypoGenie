import json, os, subprocess, zipfile

class CVEDataProcessor:
    def __init__(self, cve_id: str, cve_json: str = None):
        self.cve_id = cve_id
        self.cve_json = cve_json

    def knowledge_builder_setup(cve_path: str) -> dict:
        """
        Loads the cve json file from the given path
        """
        if not os.path.exists(cve_path):
            raise FileNotFoundError(f"❌ File not found at {cve_path}")
        return json.loads(open(cve_path, "r").read())

    def pre_reqs_builder_setup(cve_info: dict) -> str:
        """
        Clones a repo to a the parent of given commit and returns the directory tree of the repo
        """
        cur_dir = os.getcwd()
        os.chdir("simulation_environments/")

        if not os.path.exists(cve_info["project"]):
            subprocess.run(f"git clone {cve_info['git_url']}.git", shell=True, timeout=300)
            os.chdir(cve_info["project"])
            subprocess.run(f"git checkout {cve_info['hash']}~1", shell=True, timeout=300)
        else:
            os.chdir(cve_info["project"])
        os.environ['REPO_PATH'] = f"{cve_info['project']}/"
        dir_tree = subprocess.run("tree -d", shell=True, capture_output=True).stdout.decode("utf-8")
        os.chdir(cur_dir)

        return dir_tree
    
    def run(self, code_url: str = "") -> dict:
        cur_dir = os.getcwd()
        # 1) If cache exists, load cve from cache
        if self.cve_json:
            if os.path.exists(self.cve_json):
                cve = json.loads(open(self.cve_json, "r").read()).get(self.cve_id)
                if not cve:
                    raise ValueError(f"❌ {self.cve_id} not found in cache file")
            else:
                raise FileNotFoundError(f"❌ {self.cve_id} cache file not found at {self.cve_json}")
        
        else:
            raise ValueError("❌ CVE JSON cache file path must be provided")
        
        # 2) download the vulnerable tag version of the repo
        subprocess.run("rm -rf simulation_environments/*", shell=True)
        os.chdir("simulation_environments/")
        subprocess.run(f"wget {cve['sw_version_wget']}", shell=True)

        zip_name = [file for file in os.listdir(".") if file.endswith(".zip")][0]
        result = subprocess.run(f"unzip {zip_name}", shell=True)
        if result.returncode != 0:
            with zipfile.ZipFile(zip_name, 'r') as zf:
                zf.extractall(".")

        dir_name = [file for file in os.listdir(".") if os.path.isdir(file)][0]
        os.chdir(dir_name)
        os.environ['REPO_PATH'] = f"{dir_name}/"

        # 3) get the directory tree of the repo
        cve['dir_tree'] = subprocess.run("tree -d", shell=True, capture_output=True).stdout.decode("utf-8")
        cve['repo_path'] = f"{dir_name}/"
        os.chdir(cur_dir)

        return cve
