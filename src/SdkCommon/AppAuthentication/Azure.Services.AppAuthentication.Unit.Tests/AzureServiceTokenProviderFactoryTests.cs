// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.Azure.Services.AppAuthentication.TestCommon;
using System;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.Azure.Services.AppAuthentication.Unit.Tests
{
    /// <summary>
    /// Test cases for AzureServiceTokenProviderFactory class. AzureServiceTokenProviderFactory is an internal class. 
    /// Test that the right type of provider is returned based on the connection string. 
    /// </summary>
    public class AzureServiceTokenProviderFactoryTests
    {
        [Fact]
        public void AzureCliValidTest()
        {
            var provider = AzureServiceTokenProviderFactory.Create(Constants.AzureCliConnectionString, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.AzureCliConnectionString, provider.ConnectionString);
            Assert.IsType<AzureCliAccessTokenProvider>(provider);

            provider = AzureServiceTokenProviderFactory.Create(Constants.AzureCliConnectionStringWithSpaces, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.AzureCliConnectionStringWithSpaces, provider.ConnectionString);
            Assert.IsType<AzureCliAccessTokenProvider>(provider);
        }

        /// <summary>
        /// If DevelopmentTool in the connection string is invalid , an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliInvalidDeveloperToolTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.InvalidDeveloperToolConnectionString, Constants.AzureAdInstance));

            Assert.Contains(Constants.InvalidConnectionString, exception.ToString());
        }

        /// <summary>
        /// If RunAs in the connection string is invalid , an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliInvalidRunAsTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.InvalidRunAsConnectionString, Constants.AzureAdInstance));

            Assert.Contains(Constants.InvalidConnectionString, exception.ToString());
        }

        /// <summary>
        /// If a key in the connection string is empty, an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliInvalidConnectionStringTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.AzureCliConnectionStringNoRunAs, Constants.AzureAdInstance));

            Assert.Contains(Constants.InvalidConnectionString, exception.ToString());

            exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.AzureCliConnectionStringWithEmptyDeveloperTool, Constants.AzureAdInstance));

            Assert.Contains(Constants.InvalidConnectionString, exception.ToString());
        }

        /// <summary>
        /// If a key in the connection string is repeated, an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliRepeatedKeyConnectionStringTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.AzureCliConnectionStringRepeatedRunAs, Constants.AzureAdInstance));

            Assert.Contains(Constants.KeyRepeatedInConnectionString, exception.ToString());
        }

        /// <summary>
        /// If the connection string is not in the correct format, an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliIncorrectFormatConnectionStringTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.IncorrectFormatConnectionString, Constants.AzureAdInstance));

            Assert.Contains(Constants.NotInProperFormatError, exception.ToString());
        }

        /// <summary>
        /// If the connection string is null or empty, an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliConnectionStringNullOrEmptyTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(null, Constants.AzureAdInstance));

            Assert.Contains(Constants.ConnectionStringEmpty, exception.ToString());

            exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(string.Empty, Constants.AzureAdInstance));

            Assert.Contains(Constants.ConnectionStringEmpty, exception.ToString());
        }

        /// <summary>
        /// If the connection string is RunAs App and does not have a certificate location or app key, an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliConnectionStringNoCertLocationOrAppKeyTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.AppConnStringNoLocationOrAppKey, Constants.AzureAdInstance));

            Assert.Contains(Constants.ConnectionStringMissingCertLocation, exception.ToString());
        }

        /// <summary>
        /// If the connection string has invalid cert location, an exception should be thrown. 
        /// </summary>
        [Fact]
        public void AzureCliConnectionStringInvalidCertLocationTest()
        {
            var exception = Assert.Throws<ArgumentException>(() => AzureServiceTokenProviderFactory.Create(Constants.CertificateConnStringThumbprintInvalidLocation, Constants.AzureAdInstance));

            Assert.Contains(Constants.InvalidCertLocationError, exception.ToString());
        }

        /// <summary>
        /// If connection string ends with "; ", then the parser should ignore the white space and continue. 
        /// </summary>
        [Fact]
        public void AzureCliConnectionStringEndsWithSpaceTest()
        {
            var provider = AzureServiceTokenProviderFactory.Create(Constants.AzureCliConnectionStringEndingWithSemiColonAndSpace, Constants.AzureAdInstance);

            Assert.NotNull(provider);
            Assert.Equal(Constants.AzureCliConnectionStringEndingWithSemiColonAndSpace, provider.ConnectionString);
            Assert.IsType<AzureCliAccessTokenProvider>(provider);
        }

        [Fact]
        public void ActiveDirectoryIntegratedValidTest()
        {
            var provider = AzureServiceTokenProviderFactory.Create(Constants.ActiveDirectoryIntegratedConnectionString, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.ActiveDirectoryIntegratedConnectionString, provider.ConnectionString);
        }


        [Fact]
        public void ManagedServiceIdentityValidTest()
        {
            var provider = AzureServiceTokenProviderFactory.Create(Constants.ManagedServiceIdentityConnectionString, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.ManagedServiceIdentityConnectionString, provider.ConnectionString);
            Assert.IsType<MsiAccessTokenProvider>(provider);
        }

        [Fact]
        public void ManagedUserAssignedIdentityValidTest()
        {
            var provider = AzureServiceTokenProviderFactory.Create(Constants.ManagedUserAssignedIdentityConnectionString, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.ManagedUserAssignedIdentityConnectionString, provider.ConnectionString);
            Assert.IsType<MsiAccessTokenProvider>(provider);
        }

        [Fact]
        public void CertValidTest()
        {
            var provider = AzureServiceTokenProviderFactory.Create(Constants.CertificateConnStringThumbprintLocalMachine, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.CertificateConnStringThumbprintLocalMachine, provider.ConnectionString);
            Assert.IsType<ClientCertificateAzureServiceTokenProvider>(provider);

            provider = AzureServiceTokenProviderFactory.Create(Constants.CertificateConnStringThumbprintCurrentUser, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.CertificateConnStringThumbprintCurrentUser, provider.ConnectionString);
            Assert.IsType<ClientCertificateAzureServiceTokenProvider>(provider);

            provider = AzureServiceTokenProviderFactory.Create(Constants.CertificateConnStringSubjectNameCurrentUser, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.CertificateConnStringSubjectNameCurrentUser, provider.ConnectionString);
            Assert.IsType<ClientCertificateAzureServiceTokenProvider>(provider);

            provider = AzureServiceTokenProviderFactory.Create(Constants.CertificateConnStringKeyVaultSecretIdentifier, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.CertificateConnStringKeyVaultSecretIdentifier, provider.ConnectionString);
            Assert.IsType<ClientCertificateAzureServiceTokenProvider>(provider);
        }

        [Fact]
        public void ClientSecretValidTest()
        {
            var provider = AzureServiceTokenProviderFactory.Create(Constants.ClientSecretConnString, Constants.AzureAdInstance);
            Assert.NotNull(provider);
            Assert.Equal(Constants.ClientSecretConnString, provider.ConnectionString);
            Assert.IsType<ClientSecretAccessTokenProvider>(provider);
        }

        /// <summary>
        /// UrlDecode handles null input, returning null.
        /// </summary>
        [Fact]
        public void UrlDecodeNull()
        {
            var actual = AzureServiceTokenProviderFactory.PercentDecode(null);
            Assert.Null(actual);
        }

        /// <summary>
        /// If UrlDecode does not find any %-sequences, it directly returns its input.
        /// </summary>
        [Fact]
        public void UrlDecodeReferenceEquals()
        {
            var expected = "expected";
            var actual = AzureServiceTokenProviderFactory.PercentDecode(expected);
            Assert.Same(actual, expected);
        }

        /// <summary>
        /// If UrlDecode encounters an invalid sequence, it emits it directly to the output
        /// </summary>
        [Fact]
        public void UrlDecodeInvalid()
        {
            var expected = "%xx";
            var actual = AzureServiceTokenProviderFactory.PercentDecode(expected);
            Assert.Same(actual, expected);
        }

        /// <summary>
        /// UrlDecode handles all sequences in the ordinal range 0..255.
        /// </summary>
        [Fact]
        public void UrlDecodeSequence()
        {
            IEnumerable<Tuple<char, int>> Nibbles()
            {
                yield return Tuple.Create('0', 0);
                yield return Tuple.Create('1', 1);
                yield return Tuple.Create('2', 2);
                yield return Tuple.Create('3', 3);
                yield return Tuple.Create('4', 4);
                yield return Tuple.Create('5', 5);
                yield return Tuple.Create('6', 6);
                yield return Tuple.Create('7', 7);
                yield return Tuple.Create('8', 8);
                yield return Tuple.Create('9', 9);
                yield return Tuple.Create('a', 10);
                yield return Tuple.Create('b', 11);
                yield return Tuple.Create('c', 12);
                yield return Tuple.Create('d', 13);
                yield return Tuple.Create('e', 14);
                yield return Tuple.Create('f', 15);
                yield return Tuple.Create('A', 10);
                yield return Tuple.Create('B', 11);
                yield return Tuple.Create('C', 12);
                yield return Tuple.Create('D', 13);
                yield return Tuple.Create('E', 14);
                yield return Tuple.Create('F', 15);
            }
            foreach (var msb in Nibbles())
            {
                foreach (var lsb in Nibbles())
                {
                    var input = $"%{msb.Item1}{lsb.Item1}";
                    var expected = $"{(char)(msb.Item2 * 16 + lsb.Item2)}";
                    var actual = AzureServiceTokenProviderFactory.PercentDecode(input);
                    Assert.Equal(actual, expected);
                }
            }
        }

        /// <summary>
        /// UrlDecode handles incomplete sequences at the end of the string.
        /// </summary>
        [Fact]
        public void UrlDecodeTruncated()
        {
            var expected = "expected%2";
            var actual = AzureServiceTokenProviderFactory.PercentDecode(expected);
            Assert.Equal(actual, expected);
        }

        [Fact]
        public void UrlDecodeComplex()
        {
            var input = "first%3bmiddle%3blast";
            var expected = "first;middle;last";
            var actual = AzureServiceTokenProviderFactory.PercentDecode(input);
            Assert.Equal(actual, expected);
        }
    }
}
