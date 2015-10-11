package org.kanga.dist;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Arrays;
import static java.lang.System.err;
import static java.lang.System.exit;
import static java.lang.System.in;
import static java.lang.System.out;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.S3ClientOptions;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class S3Test {
    private static final AWSCredentialsProvider creds =
        new AWSCredentialsProvider() {
            public AWSCredentials getCredentials() {
                return new BasicAWSCredentials(
                    "access_key",
                    "secret_key");
            }

            public void refresh() { }
        };

    private static final int BUFFER_SIZE = 65536;

    private static final Options options = new Options()
        .addOption(Option.builder("b").longOpt("bucket").hasArg()
                   .argName("bucketName").required()
                   .desc("Name of the S3 bucket to access").build())
        .addOption(Option.builder("o").longOpt("object").hasArg()
                   .argName("objectName").required()
                   .desc("Name of the object to access").build())
        .addOption(Option.builder("P").longOpt("intercept").hasArg()
                   .argName("host[:port]")
                   .desc("Intercept host or host:port to use").build())
        .addOption(Option.builder("k").longOpt("kmsKeyId").hasArg()
                   .argName("keyId").required()
                   .desc("KMS customer master key id to use").build())
        .addOption(Option.builder("r").longOpt("read")
                   .desc("Read the S3 object and decrypt it").build())
        .addOption(Option.builder("w").longOpt("write")
                   .desc("Encrypt and write the S3 object").build())
        ;

    public static void main(String[] args) throws Exception {
        CommandLine cmdLine;

        try {
            cmdLine = new DefaultParser().parse(options, args);
        }
        catch (ParseException e) {
            err.println(e);
            PrintWriter errWriter = new PrintWriter(err);
            new HelpFormatter().printHelp(
                errWriter, 80, "S3Test",
                "Read or write KMS client-side encrypted S3 objects.\n\n",
                options, 4, 8, "", true);
            errWriter.flush();
            exit(1);
            return; // To placate Java and how it doesn't understand exit.
        }

        String bucketName = cmdLine.getOptionValue('b');
        String objectName = cmdLine.getOptionValue('o');
        String interceptHost = cmdLine.getOptionValue('P');
        int interceptPort = 80;
        String kmsCMKId = cmdLine.getOptionValue('k');
        boolean write = cmdLine.hasOption('w');

        ClientConfiguration clientConfig = new ClientConfiguration();
        AWSKMSClient kms = new AWSKMSClient(creds, clientConfig);
        if (interceptHost != null) {
            kms.setEndpoint(interceptHost);
        }
            
        KMSEncryptionMaterialsProvider materialProvider =
            new KMSEncryptionMaterialsProvider(kmsCMKId);
        CryptoConfiguration cryptoConfig =
            new CryptoConfiguration().withKmsRegion(Regions.US_WEST_2);
        
        AmazonS3EncryptionClient encryptionClient =
            new AmazonS3EncryptionClient(
                kms, creds, materialProvider, clientConfig, cryptoConfig, null)
            .withRegion(Regions.US_WEST_2);

        encryptionClient.setS3ClientOptions(
            new S3ClientOptions().withPathStyleAccess(false));

        if (interceptHost != null) {
            encryptionClient.setEndpoint(interceptHost);
        }

        if (write) {
            // Upload object using the encryption client.
            ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
            byte[] buffer = new byte[BUFFER_SIZE];
            int nRead;

            while ((nRead = in.read(buffer)) != -1) {
                plaintext.write(buffer, 0, nRead);
            }
        
            encryptionClient.putObject(
                new PutObjectRequest(
                    bucketName,
                    objectName,
                    new ByteArrayInputStream(plaintext.toByteArray()),
                    new ObjectMetadata()));
        } else {
            // Download object using the encryption client.
            S3Object result = encryptionClient.getObject(
                new GetObjectRequest(bucketName, objectName));
            byte[] buffer = new byte[BUFFER_SIZE];
            InputStream plaintext = result.getObjectContent();
            int nRead;

            while ((nRead = plaintext.read(buffer)) != -1) {
                out.write(buffer, 0, nRead);
            }
        }
    }
}
