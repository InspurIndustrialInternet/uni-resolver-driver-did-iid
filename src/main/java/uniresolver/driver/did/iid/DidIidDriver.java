package uniresolver.driver.did.iid;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.did.parser.ParserException;
import org.apache.http.HttpEntity;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniresolver.ResolutionException;
import uniresolver.driver.Driver;
import uniresolver.result.ResolveDataModelResult;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import foundation.identity.did.Service;
import uniresolver.driver.did.iid.Util.Base64;


public class DidIidDriver implements Driver {

    private static Logger log = LoggerFactory.getLogger(DidIidDriver.class);

    public static final Pattern DID_IID_PATTERN = Pattern.compile("^did:iid:([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,65})$");

    public static final String[] DIDDOCUMENT_PUBLICKEY_TYPES = new String[]{"Secp256k1"};

    public static final String[] DIDDOCUMENT_AUTHENTICATION_TYPES = new String[]{"Secp256k1"};

    public static final String DEFAULT_IID_URL = "http://117.73.2.209:9999";

    public static final HttpClient DEFAULT_HTTP_CLIENT = HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy()).build();

    private String iidUrl = DEFAULT_IID_URL;

    private HttpClient httpClient = DEFAULT_HTTP_CLIENT;

    public static void main(String[] args) throws ResolutionException, IllegalArgumentException, ParserException {
        DID did = DID.fromString("did:iid:3QUs61mk7a9CdCpckriQbA5emw8pubj6RMtHXP6gD66YbcungS6w2sa");
        ResolveDataModelResult rdm1 = new DidIidDriver().resolve(did, Map.of());
        System.out.println(rdm1);
    }

    public DidIidDriver() {
    }

    @Override
    public ResolveDataModelResult resolve(DID did, Map<String, Object> resolveOptions) throws ResolutionException {
        log.info("进入iid解析方法");
        String didString = did.getDidString();
        // match
        Matcher matcher = DID_IID_PATTERN.matcher(didString);
        if (!matcher.matches()) {
            return null;
        }
        // fetch data from iid_service
        String resolveUrl = this.getIIDUrl() + "/iidservice/did/v1/get/" + Base64.encode(didString.getBytes(StandardCharsets.UTF_8));
        HttpGet httpGet = new HttpGet(resolveUrl);

        // find the DDO
        JSONObject didDocumentDO;
        try {
            CloseableHttpResponse httpResponse = (CloseableHttpResponse) this.getHttpClient().execute(httpGet);
            if (httpResponse.getStatusLine().getStatusCode() != 200) {
                log.info("iid解析失败");
                throw new ResolutionException("Cannot retrieve DDO for `" + did + "` from `" + this.getIIDUrl() + ": " + httpResponse.getStatusLine());
            }
            // extract payload
            HttpEntity httpEntity = httpResponse.getEntity();
            String entityString = EntityUtils.toString(httpEntity);
            EntityUtils.consume(httpEntity);
            //  get DDO
            JSONObject jo = new JSONObject(entityString);
            didDocumentDO = jo.getJSONObject("data").getJSONObject("didDocument");

        } catch (IOException ex) {
            log.info("iid解析失败" + ex.getMessage());
            throw new ResolutionException("Cannot retrieve DDO info for `" + did + "` from `" + this.getIIDUrl() + "`: " + ex.getMessage(), ex);
        } catch (JSONException jex) {
            log.info("iid解析失败" + jex.getMessage());
            throw new ResolutionException("Cannot parse JSON response from `" + this.getIIDUrl() + "`: " + jex.getMessage(), jex);
        }
        // context
        List<String> context = new ArrayList<>();
        context.add(didDocumentDO.getString("@context"));
        List<URI> contexts = context.stream()
                // the following context is added by default
                .filter(con -> !"https://w3id.org/did/v1".equals(con))
                .map(URI::create)
                .collect(Collectors.toList());
        // DDO publicKeys
        // index 0 is auth key
        JSONObject firstKeyJO = didDocumentDO.getJSONArray("publicKey").getJSONObject(0);
        // index 1 is recovery key
        JSONObject secondKeyJO = didDocumentDO.getJSONArray("publicKey").getJSONObject(1);
        //verificationMethod
        List<Map<String, Object>> verificationMethod = new ArrayList<>();
        Map<String, Object> verificationMethodMap = new HashMap<>();
        verificationMethodMap.put("verificationMethod1", VerificationMethod.builder()
                .controller(firstKeyJO.getString("id"))
                .publicKeyHex(firstKeyJO.getString("publicKeyHex"))
                .build());
        Map<String, Object> verificationMethodMap2 = new HashMap<>();
        verificationMethodMap2.put("verificationMethod2", VerificationMethod.builder()
                .controller(secondKeyJO.getString("id"))
                .publicKeyHex(secondKeyJO.getString("publicKeyHex"))
                .build());
        verificationMethod.add(verificationMethodMap);
        verificationMethod.add(verificationMethodMap2);
        //authentication
        List<Map<String, Object>> authentication = new ArrayList<>();
        Map<String, Object> authenticationMap = new HashMap<>();
        authenticationMap.put("authentication", VerificationMethod.builder()
                .controller(firstKeyJO.getString("id"))
                .build());
        authentication.add(authenticationMap);
        //services
        List<Map<String, Object>> services = new ArrayList<>();
        JSONArray serviceJA = didDocumentDO.getJSONArray("service");
        for (int i = 0; i < serviceJA.length(); i++) {
            JSONObject service = serviceJA.getJSONObject(i);
            Map<String, Object> serviceMap = new HashMap<>();
            serviceMap.put("service", Service.builder()
                    .type(service.getString("type"))
                    .serviceEndpoint(service.getString("serviceEndpoint"))
                    .build());
            services.add(serviceMap);
        }
        // create DDO
        DIDDocument didDocument = DIDDocument.builder()
                .contexts(contexts)
                .id(did.toUri())
                .verificationMethods(intoVerificationMethods(verificationMethod))
                .authenticationVerificationMethods(intoVerificationMethods(authentication))
                .services(intoServices(services))
                .build();

        // create Method METADATA
        Map<String, Object> methodMetadata = new LinkedHashMap<>();
        methodMetadata.put("version", didDocumentDO.getInt("version"));
        methodMetadata.put("proof", didDocumentDO.getJSONObject("proof").toMap());
        methodMetadata.put("created", didDocumentDO.getString("created"));
        methodMetadata.put("updated", didDocumentDO.getString("updated"));

        // done
        log.info("iid解析结束");
        return ResolveDataModelResult.build(null, didDocument, methodMetadata);
    }

    private static List<VerificationMethod> intoVerificationMethods(List<Map<String, Object>> list) {
        return intoBeans(list, VerificationMethod::fromMap);
    }

    private static List<Service> intoServices(List<Map<String, Object>> list) {
        return intoBeans(list, Service::fromMap);
    }

    private static <T> List<T> intoBeans(List<Map<String, Object>> list, Function<Map<String, Object>, T> mapper) {
        return list.stream()
                .map(mapper)
                .collect(Collectors.toList());
    }

    @Override
    public Map<String, Object> properties() {

        Map<String, Object> properties = new HashMap<>();
        properties.put("iidUrl", this.getIIDUrl());

        return properties;
    }

    /*
     * Getters and setters
     */

    public String getIIDUrl() {

        return this.iidUrl;
    }

    public void setIIDUrl(String IIDUrl) {
        this.iidUrl = IIDUrl;
    }

    public HttpClient getHttpClient() {

        return this.httpClient;
    }

    public void setHttpClient(HttpClient httpClient) {

        this.httpClient = httpClient;
    }
}
