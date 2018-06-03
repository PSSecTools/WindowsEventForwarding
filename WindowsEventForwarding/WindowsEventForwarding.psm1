#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modul "WindowsEventForwarding"
# Author:  Andreas Bellstedt

#region type defintion
#---------------------

#endregion type defintion


#region Constants
#--------------------------
New-Variable -Option ReadOnly, Constant -Scope Script -Name BaseType -Value "WEF"

#endregion


#region basic functions
#----------------------
. $psscriptroot\Functions\Get-WEFSubscription.ps1

#endregion


#region Helper functions
#-----------------------

#endregion
