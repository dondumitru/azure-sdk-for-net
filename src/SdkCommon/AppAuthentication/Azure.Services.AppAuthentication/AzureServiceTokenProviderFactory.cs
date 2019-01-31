// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.Azure.Services.AppAuthentication
{
    /// <summary>
    /// Creates an access token provider based on the connection string. 
    /// </summary>
    internal class AzureServiceTokenProviderFactory
    {
        private const string RunAs = "RunAs";
        private const string Developer = "Developer";
        private const string AzureCli = "AzureCLI";
        private const string VisualStudio = "VisualStudio";
        private const string DeveloperTool = "DeveloperTool";
        private const string CurrentUser = "CurrentUser";
        private const string App = "App";
        private const string AppId = "AppId";
        private const string AppKey = "AppKey";
        private const string AppKeyPercentEncoded = "AppKeyPercentEncoded";
        private const string TenantId = "TenantId";
        private const string CertificateSubjectName = "CertificateSubjectName";
        private const string CertificateThumbprint = "CertificateThumbprint";
        private const string KeyVaultSecretIdentifier = "KeyVaultSecretIdentifier";
        private const string CertificateStoreLocation = "CertificateStoreLocation";
        
        /// <summary>
        /// Returns a specific token provider based on authentication option specified in the connection string. 
        /// </summary>
        /// <param name="connectionString">Connection string with authentication option and related parameters.</param>
        /// <param name="azureAdInstance"></param>
        /// <returns></returns>
        internal static NonInteractiveAzureServiceTokenProviderBase Create(string connectionString, string azureAdInstance)
        {
            Dictionary<string, string> connectionSettings = ParseConnectionString(connectionString);

            NonInteractiveAzureServiceTokenProviderBase azureServiceTokenProvider;

            ValidateAttribute(connectionSettings, RunAs, connectionString);

            string runAs = connectionSettings[RunAs];

            if (string.Equals(runAs, Developer, StringComparison.OrdinalIgnoreCase))
            {
                // If RunAs=Developer
                ValidateAttribute(connectionSettings, DeveloperTool, connectionString);

                // And Dev Tool equals AzureCLI or VisualStudio
                if (string.Equals(connectionSettings[DeveloperTool], AzureCli,
                    StringComparison.OrdinalIgnoreCase))
                {
                    azureServiceTokenProvider = new AzureCliAccessTokenProvider(new ProcessManager());
                }
                else if (string.Equals(connectionSettings[DeveloperTool], VisualStudio,
                    StringComparison.OrdinalIgnoreCase))
                {
                    azureServiceTokenProvider = new VisualStudioAccessTokenProvider(new ProcessManager());
                }
                else
                {
                    throw new ArgumentException($"Connection string {connectionString} is not valid. {DeveloperTool} '{connectionSettings[DeveloperTool]}' is not valid. " +
                                                $"Allowed values are {AzureCli} or {VisualStudio}");
                }
            }
            else if (string.Equals(runAs, CurrentUser, StringComparison.OrdinalIgnoreCase))
            {
                // If RunAs=CurrentUser
                azureServiceTokenProvider = new WindowsAuthenticationAzureServiceTokenProvider(new AdalAuthenticationContext(), azureAdInstance);
            }
            else if (string.Equals(runAs, App, StringComparison.OrdinalIgnoreCase))
            {
                // If RunAs=App
                // If AppId key is present, use certificate, client secret, or MSI (with user assigned identity) based token provider
                if (connectionSettings.ContainsKey(AppId))
                {
                    ValidateAttribute(connectionSettings, AppId, connectionString);
                    ValidateAttribute(connectionSettings, TenantId, connectionString);

                    if (connectionSettings.ContainsKey(CertificateStoreLocation))
                    {
                        ValidateAttributes(connectionSettings, new List<string> { CertificateSubjectName, CertificateThumbprint }, connectionString);
                        ValidateAttribute(connectionSettings, CertificateStoreLocation, connectionString);
                        ValidateStoreLocation(connectionSettings, connectionString);

                        azureServiceTokenProvider =
                            new ClientCertificateAzureServiceTokenProvider(
                                connectionSettings[AppId],
                                connectionSettings.ContainsKey(CertificateThumbprint)
                                    ? connectionSettings[CertificateThumbprint]
                                    : connectionSettings[CertificateSubjectName],
                                connectionSettings.ContainsKey(CertificateThumbprint)
                                    ? ClientCertificateAzureServiceTokenProvider.CertificateIdentifierType.Thumbprint
                                    : ClientCertificateAzureServiceTokenProvider.CertificateIdentifierType.SubjectName,
                                connectionSettings[CertificateStoreLocation],
                                connectionSettings[TenantId],
                                azureAdInstance);
                    }
                    else if (connectionSettings.ContainsKey(CertificateThumbprint) ||
                             connectionSettings.ContainsKey(CertificateSubjectName))
                    {
                        // if certificate thumbprint or subject name are specified but certificate store location is not, throw error
                        throw new ArgumentException($"Connection string {connectionString} is not valid. Must contain '{CertificateStoreLocation}' attribute and it must not be empty " +
                                                    $"when using '{CertificateThumbprint}' and '{CertificateSubjectName}' attributes");
                    }
                    else if (connectionSettings.ContainsKey(KeyVaultSecretIdentifier))
                    {
                        azureServiceTokenProvider =
                            new ClientCertificateAzureServiceTokenProvider(
                                connectionSettings[AppId],
                                connectionSettings[KeyVaultSecretIdentifier],
                                ClientCertificateAzureServiceTokenProvider.CertificateIdentifierType.KeyVaultSecretIdentifier,
                                null, // storeLocation unused
                                connectionSettings[TenantId],
                                azureAdInstance);
                    }
                    else if (connectionSettings.ContainsKey(AppKey))
                    {
                        ValidateAttribute(connectionSettings, AppKey, connectionString);

                        azureServiceTokenProvider =
                            new ClientSecretAccessTokenProvider(
                                connectionSettings[AppId],
                                connectionSettings[AppKey],
                                connectionSettings[AppKey], // literal value in connection string to redact
                                connectionSettings[TenantId],
                                azureAdInstance);
                    }
                    else if (connectionSettings.ContainsKey(AppKeyPercentEncoded))
                    {
                        ValidateAttribute(connectionSettings, AppKeyPercentEncoded, connectionString);

                        azureServiceTokenProvider =
                            new ClientSecretAccessTokenProvider(
                                connectionSettings[AppId],
                                PercentDecode(connectionSettings[AppKeyPercentEncoded]),
                                connectionSettings[AppKeyPercentEncoded], // literal value in connection string to redact
                                connectionSettings[TenantId],
                                azureAdInstance);
                    }
                    else
                    {
                        // If certificate or client secret are not specified, use the specified managed identity
                        azureServiceTokenProvider = new MsiAccessTokenProvider(connectionSettings[AppId]);
                    }
                }
                else
                {
                    // If AppId is not specified, use Managed Service Identity
                    azureServiceTokenProvider = new MsiAccessTokenProvider();
                }
            }
            else
            {
                throw new ArgumentException($"Connection string {connectionString} is not valid. RunAs value '{connectionSettings[RunAs]}' is not valid.  " +
                                            $"Allowed values are {Developer}, {CurrentUser}, or {App}");
            }

            azureServiceTokenProvider.ConnectionString = connectionString;

            return azureServiceTokenProvider;

        }

        /// <summary>
        /// Implement percent-decoding for a string.  This is equivalent to HttpUtility.UrlDecode (without
        /// as many optimizations).  However, in .Net Standard 1.4, HttpUtility drags in an additional
        /// dependency, so to keep AppAuthentication as streamlined as possible, PercentDecode is
        /// re-implemented here.  If AppAuthentication support for .Net Standard 1.4 is removed, this method
        /// could probably be removed and replaced with a call to HttpUtility.UrlDecode.
        /// </summary>
        /// <param name="input"></param>
        /// <returns>The input string with %-encoded sequences replaced with their native characters.</returns>
        internal static string PercentDecode(string input)
        {
            int? CharDecode(char ch)
            {
                if ((ch >= '0') && (ch <= '9'))
                {
                    return ch - '0';
                }
                if ((ch >= 'a') && (ch <= 'f'))
                {
                    return ch - 'a' + 10;
                }
                if ((ch >= 'A') && (ch <= 'F'))
                {
                    return ch - 'A' + 10;
                }
                return null;
            }
            if (input == null)
            {
                return null;
            }
            var resultBuilder = default(StringBuilder); // If the input string contains no %-sequences, then no allocations will be performed.
            var builderIdx = 0; // resultBuilder contains the input string up to, but not including, this index.
            var currIdx = 0; // The index of the next %-sequence to decode.
            while (true)
            {
                currIdx = input.IndexOf('%', currIdx); // The index of the next %-sequence to decode.
                if (currIdx == -1 || currIdx + 3 > input.Length)
                {
                    // Stop processing if no further %-sequences were found, or
                    // if the trailing %sequence is truncated short by the end of
                    // the string.
                    break;
                }
                var msb = CharDecode(input[currIdx + 1]);
                var lsb = CharDecode(input[currIdx + 2]);
                if (!msb.HasValue || !lsb.HasValue)
                {
                    // Check for invalid %-sequences.  A valid %-sequence, like "%3b", will transfer (below) as a single
                    // character, like ';', while an invalid sequence like "%qf" will hit this if-statement, causing it
                    // to transfer verbatim as the 3-character sequence '%' 'q' 'f' without any decoding.
                    ++currIdx;
                    continue;
                }
                if (resultBuilder == null)
                {
                    // Decoding is actually required, so we need to allocate a buffer.
                    resultBuilder = new StringBuilder();
                }
                if (builderIdx < currIdx)
                {
                    // Transfer any non-%-seqeuences from the input string, up to but not including
                    // the currently-recognized %-sequence.
                    resultBuilder.Append(input, builderIdx, currIdx - builderIdx);
                }
                // Append the single decoded character.
                resultBuilder.Append((char)(msb * 16 + lsb));
                // Advance the indexes past the current %-sequence.
                builderIdx = currIdx + 3;
                currIdx = currIdx + 3;
            }
            if (resultBuilder == null)
            {
                // If we didn't allocate the builder, that is our signal that no decoding was performed,
                // in which case we just return the input string.
                return input;
            }
            if (builderIdx < input.Length)
            {
                // Append any trailing non-%-sequence characters from the input onto the result.
                resultBuilder.Append(input, builderIdx, input.Length - builderIdx);
            }
            return resultBuilder.ToString();
        }

        private static void ValidateAttribute(Dictionary<string, string> connectionSettings, string attribute,
        string connectionString)
        {
            if (connectionSettings != null &&
                (!connectionSettings.ContainsKey(attribute) || string.IsNullOrWhiteSpace(connectionSettings[attribute])))
            {
                throw new ArgumentException($"Connection string {connectionString} is not valid. Must contain '{attribute}' attribute and it must not be empty.");
            }
        }

        /// <summary>
        /// Throws an exception if none of the attributes are in the connection string
        /// </summary>
        /// <param name="connectionSettings">List of key value pairs in the connection string</param>
        /// <param name="attributes">List of attributes to test</param>
        /// <param name="connectionString">The connection string specified</param>
        private static void ValidateAttributes(Dictionary<string, string> connectionSettings, List<string> attributes,
        string connectionString)
        {
            if (connectionSettings != null)
            {
                foreach (string attribute in attributes)
                {
                    if (connectionSettings.ContainsKey(attribute))
                    {
                        return;
                    }
                }

                throw new ArgumentException($"Connection string {connectionString} is not valid. Must contain at least one of {string.Join(" or ", attributes)} attributes.");
            }
        }

        private static void ValidateStoreLocation(Dictionary<string, string> connectionSettings, string connectionString)
        {
            if (connectionSettings != null && connectionSettings.ContainsKey(CertificateStoreLocation))
            {
                if (!string.IsNullOrEmpty(connectionSettings[CertificateStoreLocation]))
                {
                    StoreLocation location;
                    string storeLocation = connectionSettings[CertificateStoreLocation];

                    bool parseSucceeded = Enum.TryParse(storeLocation, true, out location);
                    if (!parseSucceeded)
                    {
                        throw new ArgumentException(
                            $"Connection string {connectionString} is not valid. StoreLocation {storeLocation} is not valid. Valid values are CurrentUser and LocalMachine.");
                    }
                }

            }
        }

        private static Dictionary<string, string> ParseConnectionString(string connectionString)
        {
            Dictionary<string, string> connectionSettings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (!string.IsNullOrWhiteSpace(connectionString))
            {
                // Split by ;
                string[] splitted = connectionString.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string splitSetting in splitted)
                {
                    // Remove spaces before and after key=value
                    string setting = splitSetting.Trim();

                    // If setting is empty, continue. This is an empty space at the end e.g. "key=value; "
                    if (setting.Length == 0)
                        continue;

                    if (setting.Contains("="))
                    {
                        // Key is the first part before =
                        string[] keyValuePair = setting.Split('=');
                        string key = keyValuePair[0].Trim();

                        // Value is everything else as is
                        var value = setting.Substring(keyValuePair[0].Length + 1).Trim();

                        if (!string.IsNullOrWhiteSpace(key))
                        {
                            if (!connectionSettings.ContainsKey(key))
                            {
                                connectionSettings[key] = value;
                            }
                            else
                            {
                                throw new ArgumentException(
                                    $"Connection string {connectionString} is not in a proper format. Key '{key}' is repeated.");
                            }
                        }
                    }
                    else
                    {
                        throw new ArgumentException(
                            $"Connection string {connectionString} is not in a proper format. Expected format is Key1=Value1;Key2=Value=2;");
                    }
                }
            }
            else
            {
                throw new ArgumentException("Connection string is empty.");
            }

            return connectionSettings;
        }
    }
}
