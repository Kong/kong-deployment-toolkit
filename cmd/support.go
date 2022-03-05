/*
Copyright © 2022 John Harris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"github.com/spf13/cobra"
	// kongv1 "github.com/kong/kubernetes-ingress-controller/v2/pkg/apis/configuration/v1"
	// kongv1beta1 "github.com/kong/kubernetes-ingress-controller/v2/pkg/apis/configuration/v1beta1"
)

// supportCmd represents the base command when called without any subcommands
var supportCmd = &cobra.Command{
	Use:   "support",
	Short: "Instructions for contacting support",
	Long: `Collecting logs
It is important to provide logs to us. A single line error log does not provide much information. If it is possible, please
enable debug log by setting log_level and provide the full logs to us. If you have any logging plugin enabled, please
provide the related request logs to us as well.
Here is our KB article about enabling debug log on different platforms.

https://support.konghq.com/support/s/article/how-to-enable-debug-log

Problem with OIDC and JWT signer
On top of plugin configuration and debug log, we need a sample JWT token (For example, id_token,
access_token from your IDP). This is to help us understand how your token is signed, what claims are on the token
to debug further.

Problem observed on browsers
If you observe the issue on your browser, you may want to generate and provide a HAR file to us.
To generate HAR file, please check this article. You can also analyse the HAR file with HAR Analyzer.

Version Support Policy
Please make sure the Kong version you are running is currently within the support window to avoid any surprises.
Specifically, if you are at the end of full support (in sunset phase) Kong will not provide patches for software covered
by this sunset period.
For more detail, please check our support policy here.

Do's and Don'ts
Please do NOT use screenshot for logs and configurations. Please save your logs and configurations to different files and attach
them to the case. We highly encourage you to provide reproduce steps to us. This will significantly reduce the time for debugging
and finding a solution for you.`,
	PreRun: toggleDebug,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//RunE: func(cmd *cobra.Command, args []string) error {
	//    if rType == "" {
	//        runtime, err := guessRuntime()
	//        if err != nil {
	//            return err
	//        }
	//        rType = runtime
	//    }
	//    switch rType {
	//    case "docker":
	//        return runDocker()
	//    case "kubernetes":
	//        return runKubernetes()
	//    case "vm":
	//        fmt.Println("Not supported yet")
	//    default:
	//        fmt.Println("error")
	//    }
	//    return nil
	//},
}

func init() {
	rootCmd.AddCommand(supportCmd)
	//supportCmd.PersistentFlags().StringVarP(&rType, "runtime", "r", "", "runtime")
}
