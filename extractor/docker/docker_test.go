package docker

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/goodwithtech/deckoder/types"
	"github.com/goodwithtech/deckoder/utils"

	"github.com/goodwithtech/deckoder/extractor"
)

const (
	NormalFileMode os.FileMode = 0644
	SuFileMode     os.FileMode = 0600
)

func TestExtractFromFile(t *testing.T) {
	vectors := []struct {
		file       string // Test input file
		filterFunc types.FilterFunc
		FileMap    extractor.FileMap // Expected output
		err        error             // Expected error to occur
	}{
		{
			file:       "testdata/image1.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{"var/foo", "etc/test/bar"}),
			FileMap: extractor.FileMap{
				"etc/test/bar": {Body: []byte("bar\n"), FileMode: NormalFileMode},
				"/config": {
					Body:     []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:e641703a6c77abde58a2e2d5e506da5ac61a648bdb17fba7c3325db9d2ba4ded","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"7dfcd2c8327651024825c14e0d8752544f59c03efeca291a71e532b7e0ca66bf","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","rm /var/foo \u0026\u0026 rm -rf /etc/test \u0026\u0026 mkdir /etc/test \u0026\u0026 echo bar \u003e /etc/test/bar"],"ArgsEscaped":true,"Image":"sha256:e641703a6c77abde58a2e2d5e506da5ac61a648bdb17fba7c3325db9d2ba4ded","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"created":"2019-04-07T04:27:16.291049098Z","docker_version":"18.09.2","history":[{"created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2019-04-07T04:08:02.548475493Z","created_by":"/bin/sh -c mkdir /etc/test \u0026\u0026 touch /var/foo \u0026\u0026 touch /etc/test/test"},{"created":"2019-04-07T04:27:16.291049098Z","created_by":"/bin/sh -c rm /var/foo \u0026\u0026 rm -rf /etc/test \u0026\u0026 mkdir /etc/test \u0026\u0026 echo bar \u003e /etc/test/bar"}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:d9ff549177a94a413c425ffe14ae1cc0aa254bc9c7df781add08e7d2fba25d27","sha256:f75441026d68038ca80e92f342fb8f3c0f1faeec67b5a80c98f033a65beaef5a","sha256:a8b87ccf2f2f94b9e23308560800afa3f272aa6db5cc7d9b0119b6843889cff2"]}}`),
					FileMode: os.ModePerm,
				},
			},
			err: nil,
		},
		{
			file:       "testdata/image2.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{"home/app/Gemfile", "home/app2/Gemfile"}),
			FileMap: extractor.FileMap{
				"home/app2/Gemfile": {Body: []byte("gem"), FileMode: NormalFileMode},
				"/config": {
					Body:     []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:4fe3bbb628df60571f88cb053db9e2c9ec2f1c1e8373db9b026d0e582ef01d6d","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"7b1b7a0cfacbce82b51230bf0c6354e64cd0068e4e51180ab717890fc805bdf5","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","mv /home/app /home/app2"],"ArgsEscaped":true,"Image":"sha256:4fe3bbb628df60571f88cb053db9e2c9ec2f1c1e8373db9b026d0e582ef01d6d","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"created":"2019-04-07T05:32:59.607884934Z","docker_version":"18.09.2","history":[{"created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2019-04-07T05:32:58.27180871Z","created_by":"/bin/sh -c mkdir /home/app \u0026\u0026 echo -n gem \u003e /home/app/Gemfile"},{"created":"2019-04-07T05:32:59.607884934Z","created_by":"/bin/sh -c mv /home/app /home/app2"}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:d9ff549177a94a413c425ffe14ae1cc0aa254bc9c7df781add08e7d2fba25d27","sha256:f9e7e541d5be4537a826c4c6cb68b603a8e552c22e28ac726e9be6b22f51af44","sha256:718fb3edf377530e3713cd074d141827d05f654f6389e827c344b7fcff153025"]}}`),
					FileMode: os.ModePerm,
				},
			},
			err: nil,
		},
		{
			file:       "testdata/image3.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{"home/app/Gemfile", "home/app2/Pipfile", "home/app/Pipfile"}),
			FileMap: extractor.FileMap{
				"home/app/Pipfile": {Body: []byte("pip"), FileMode: NormalFileMode},
				"/config": {
					Body:     []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:53dca1cadfa555151d28ac616df868eed4fc935f21af393118f4fbc36d9fb24a","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"42b6c68c1704e06fbffecfee6ae5400978cf508790d563e2bda4d1b20ce93c6d","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","rm -rf /home/app \u0026\u0026 mv /home/app2 /home/app"],"ArgsEscaped":true,"Image":"sha256:53dca1cadfa555151d28ac616df868eed4fc935f21af393118f4fbc36d9fb24a","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"created":"2019-04-07T05:36:08.899764053Z","docker_version":"18.09.2","history":[{"created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2019-04-07T05:32:58.27180871Z","created_by":"/bin/sh -c mkdir /home/app \u0026\u0026 echo -n gem \u003e /home/app/Gemfile"},{"created":"2019-04-07T05:36:07.629894435Z","created_by":"/bin/sh -c mkdir /home/app2 \u0026\u0026 echo -n pip \u003e /home/app2/Pipfile"},{"created":"2019-04-07T05:36:08.899764053Z","created_by":"/bin/sh -c rm -rf /home/app \u0026\u0026 mv /home/app2 /home/app"}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:d9ff549177a94a413c425ffe14ae1cc0aa254bc9c7df781add08e7d2fba25d27","sha256:f9e7e541d5be4537a826c4c6cb68b603a8e552c22e28ac726e9be6b22f51af44","sha256:5a917ce45575a009bb5b4f462ed84522c7f642647b62a9f2b2bdfc2275f85104","sha256:50022087bbe2b08d1ce033122a56c7cf74cc1d1d6dae97a397226dd49a309c3b"]}}`),
					FileMode: os.ModePerm,
				},
			},
			err: nil,
		},
		{
			file:       "testdata/image4.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{".abc", ".def", "foo/.abc", "foo/.def", ".foo/.abc"}),
			FileMap: extractor.FileMap{
				".def":     {Body: []byte("def"), FileMode: NormalFileMode},
				"foo/.abc": {Body: []byte("abc"), FileMode: NormalFileMode},
				"/config": {
					Body:     []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:cabfb6dd9c622b8cd0efdc7bb38ed9a9d2001a32c2b5d5c174e284784df712e8","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"8290b131834ed7ef8c388a290594afeaa5daea024031a2551c8dedfc845fd09e","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","rm -rf /.foo"],"ArgsEscaped":true,"Image":"sha256:cabfb6dd9c622b8cd0efdc7bb38ed9a9d2001a32c2b5d5c174e284784df712e8","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"created":"2019-04-07T05:48:16.088980845Z","docker_version":"18.09.2","history":[{"created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2019-04-07T05:48:10.560447082Z","created_by":"/bin/sh -c echo -n abc \u003e .abc \u0026\u0026 echo -n def \u003e .def"},{"created":"2019-04-07T05:48:11.938256528Z","created_by":"/bin/sh -c mkdir foo \u0026\u0026 echo -n abc \u003e /foo/.abc \u0026\u0026 echo -n def \u003e /foo/.def"},{"created":"2019-04-07T05:48:13.188275588Z","created_by":"/bin/sh -c rm .abc /foo/.def"},{"created":"2019-04-07T05:48:14.569944213Z","created_by":"/bin/sh -c mkdir .foo \u0026\u0026 echo -n abc /.foo/.abc"},{"created":"2019-04-07T05:48:16.088980845Z","created_by":"/bin/sh -c rm -rf /.foo"}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:d9ff549177a94a413c425ffe14ae1cc0aa254bc9c7df781add08e7d2fba25d27","sha256:c42355fdc6d1a90c39b26ae5ac44c85c079f6da260def6bcb781ffcfe45ce6c9","sha256:b16629f22093ce5dfec353149661886cc1ca0c62ff30c450a82eba693eaedbd2","sha256:9717a79724f7114e32f004067a9cf96493812b2772f8a88096d1c43f7898d4f9","sha256:87c73b7beca2340705c988bb35235c66ae16b2ed2a6ce5b37b215f9bb08e7dc9","sha256:99cc8353ab2a712793601465751b9f518a35763db138e8b92b54f13e0c82d8b6"]}}`),
					FileMode: os.ModePerm,
				},
			},
			err: nil,
		},
		{
			file:       "testdata/symbolic.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{"app/once-suid.txt"}),
			FileMap: extractor.FileMap{
				"/config": {
					Body:     []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["sh"],"ArgsEscaped":true,"Image":"sha256:25aa26160d606f731f94ccf525b89a4d053dea55283b4c217ab17974470c13d2","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"2b8460ecdbc473de1619d5500fcac60b7eeca0644d861f68116d6e800476be2e","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","chmod u-s /app/once-suid.txt"],"Image":"sha256:25aa26160d606f731f94ccf525b89a4d053dea55283b4c217ab17974470c13d2","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"created":"2019-11-03T11:29:05.1794466Z","docker_version":"19.03.3","history":[{"created":"2019-10-30T23:20:37.083008444Z","created_by":"/bin/sh -c #(nop) ADD file:1141b81e5149cc37c4346ee17e282cca8c7016a9bcfeb7a54842a87ecf8419d4 in / "},{"created":"2019-10-30T23:20:37.206592274Z","created_by":"/bin/sh -c #(nop)  CMD [\"sh\"]","empty_layer":true},{"created":"2019-11-03T11:28:31.5777602Z","created_by":"/bin/sh -c #(nop) ADD file:81c0a803075715d1a6b4f75a29f8a01b21cc170cfc1bff6702317d1be2fe71a3 in /app/credentials.json "},{"created":"2019-11-03T11:28:31.7499518Z","created_by":"/bin/sh -c #(nop) COPY file:4c0973905b18418c88918f298422d66c161bc7b268cdd9dea8a5b39f0a2e2724 in /app/suid.txt "},{"created":"2019-11-03T11:28:32.4461907Z","created_by":"/bin/sh -c chmod u+s /app/suid.txt"},{"created":"2019-11-03T11:29:02.9218773Z","created_by":"/bin/sh -c #(nop) COPY file:9db1cd6af9647bf9523a117d9666de3fdd5b712ff196ee9ef831d24b459fe5c5 in /app/gid.txt "},{"created":"2019-11-03T11:29:03.6105192Z","created_by":"/bin/sh -c chmod g+s /app/gid.txt"},{"created":"2019-11-03T11:29:03.8157407Z","created_by":"/bin/sh -c #(nop) COPY file:099532e1e74e65eb216f794cf8322bfb8d79fac9789212976247040be10dd4fd in /app/once-suid.txt "},{"created":"2019-11-03T11:29:04.4828668Z","created_by":"/bin/sh -c chmod u+s /app/once-suid.txt"},{"created":"2019-11-03T11:29:05.1794466Z","created_by":"/bin/sh -c chmod u-s /app/once-suid.txt"}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:1da8e4c8d30765bea127dc2f11a17bc723b59480f4ab5292edb00eb8eb1d96b1","sha256:358229a0697da3d882c843b617236fb6329fb3ed70431a229dd7279c1957ab9b","sha256:677c191235a22a3125057f747c7f44b606e17701b7a273c1d2ff1d8dc825deea","sha256:274c73d4a7f85b7c016d8d7347eda83880f30f8ca06b75845b4f1633cd2ec001","sha256:3664c45b68a51d54ec1616866650d8cad245cb251f1cbd6d379208972c47612c","sha256:6216714b76347932abba59c7b175db61e597637129cc8001cdb7a6dc32c03f0f","sha256:98d172aa39eb52759aa79fda88452c3d78528ea21b170332cf45759c902c519a","sha256:434ba219e3907e89fe29f9b7de597fdf2305c615356f6a760e880570486fb4bb","sha256:98d172aa39eb52759aa79fda88452c3d78528ea21b170332cf45759c902c519a"]}}`),
					FileMode: os.ModePerm,
				},
				"app/once-suid.txt": {Body: []byte(""), FileMode: NormalFileMode},
			},
			err: nil,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			defer f.Close()

			d := DockerExtractor{}
			fm, err := d.ExtractFromFile(nil, f, v.filterFunc)
			if v.err != err {
				t.Errorf("err: got %v, want %v", v.err, err)
			}
			if !reflect.DeepEqual(fm, v.FileMap) {
				t.Errorf("FilesMap: got %v, want %v", fm, v.FileMap)
				for _, f := range fm {
					fmt.Println(string(f.Body))
				}
			}
		})
	}
}

func TestExtractFiles(t *testing.T) {
	vectors := []struct {
		file        string // Test input file
		filterFunc  types.FilterFunc
		filenames   []string // Target files
		permissions []os.FileMode
		FileMap     extractor.FileMap // Expected output
		opqDirs     opqDirs           // Expected output
		err         error             // Expected error to occur
	}{
		{
			file:       "testdata/normal.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{"var/foo"}),
			FileMap:    extractor.FileMap{"var/foo": {Body: []byte{}, FileMode: NormalFileMode}},
			opqDirs:    []string{},
			err:        nil,
		},
		{
			file:       "testdata/opq.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{"var/foo"}),
			FileMap: extractor.FileMap{
				"var/.wh.foo": {Body: []byte{}, FileMode: SuFileMode},
			},
			opqDirs: []string{"etc/test"},
			err:     nil,
		},
		{
			file:       "testdata/opq2.tar",
			filterFunc: utils.CreateFilterPathFunc([]string{"var/foo", "etc/test/bar"}),
			FileMap: extractor.FileMap{
				"etc/test/bar": {Body: []byte("bar\n"), FileMode: NormalFileMode},
				"var/.wh.foo":  {Body: []byte{}, FileMode: SuFileMode},
			},
			opqDirs: []string{"etc/test"},
			err:     nil,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			defer f.Close()

			d := DockerExtractor{}
			fm, opqDirs, err := d.ExtractFiles(f, v.filterFunc)
			if v.err != err {
				t.Errorf("err: got %v, want %v", v.err, err)
			}
			if !reflect.DeepEqual(opqDirs, v.opqDirs) {
				t.Errorf("opqDirs: got %v, want %v", opqDirs, v.opqDirs)
			}
			if !reflect.DeepEqual(fm, v.FileMap) {
				t.Errorf("FilesMap: got %v, want %v", fm, v.FileMap)
			}
		})
	}
}
