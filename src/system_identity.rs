//! Implementation of L2 System Identity creation

mod iam_client;
mod types;


struct SystemIdentityRetriever;

impl SystemIdentityRetriever {
  
}
// Equivalent procedure as a script:
//
// ```bash
// ############################################################
// # Get the L1 Access Token
// ############################################################
// if [ "{{.NEW_RELIC_AUTH_CLIENT_ID}}" != "" ] && [ "{{.NEW_RELIC_AUTH_CLIENT_SECRET}}" != "" ]; then
//   echo Starting with L1 System Identity...
//   RESPONSE_FILE=$TEMPORAL_FOLDER/response_token.json
//   for RETRY in 1 2 3; do
//     HTTP_CODE=$(echo '{"client_id": "{{.NEW_RELIC_AUTH_CLIENT_ID}}", "client_secret": "{{.NEW_RELIC_AUTH_CLIENT_SECRET}}", "grant_type": "client_credentials"}' | tr -d $'\n' | curl \
//       -s -S -w "%{http_code}" \
//       -H "Content-Type: application/json" \
//       -o "$RESPONSE_FILE" \
//       --data-binary @- \
//       --max-time 60 \
//       --connect-timeout 10 \
//       "$TOKEN_RENEWAL_ENDPOINT"
//     )

//     if [ $HTTP_CODE -eq 200 ]; then
//       break
//     fi

//     if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -eq 0 ]; then
//       echo "Network error occurred or no HTTP response was received. Retrying ($RETRY/3)..."
//       sleep 2
//       continue
//     else
//       if jq empty "$TEMPORAL_FOLDER/response_token.json" > /dev/null 2>&1; then
//         ERROR_MESSAGE=$(jq '.error_description // "invalid_request"' < "$TEMPORAL_FOLDER/response_token.json" | tr -d '"')
//         echo "Error getting system identity auth token. The API endpoint returned $HTTP_CODE: $ERROR_MESSAGE. Retrying ($RETRY/3)..."
//         sleep 2
//         continue
//       else
//         echo -n "Error getting system identity auth token. The API endpoint returned $HTTP_CODE: " && cat "$TEMPORAL_FOLDER/response_token.json" | tr -d '\n' && echo " Retrying ($RETRY/3)..."
//         sleep 2
//         continue
//       fi
//     fi
//   done

//   if [ $HTTP_CODE -ne 200 ]; then
//     echo "Error getting system identity auth token"
//     exit 99
//   fi

//   ACCESS_TOKEN=$(/usr/local/bin/newrelic utils jq  '.access_token' < "$RESPONSE_FILE" | tr -d '"' )

//   ############################################################
//   # Create System Identity
//   ############################################################
//   DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
//   NAME="System Identity for $(hostname) - $DATE"
//   echo Starting with L2 System Identity...

//   for RETRY in 1 2 3; do
//     HTTP_CODE=$(echo '{ "query":
//         "mutation {
//           systemIdentityCreate(
//             name: \"'$NAME'\",
//             organizationId: \"{{ .NEW_RELIC_ORGANIZATION }}\",
//             publicKey: \"'$(openssl enc -base64 -A -in "$TEMPORAL_FOLDER/pub")'\"
//           ) {
//             clientId,
//             name
//           }
//         }"
//       }' | tr -d $'\n' | curl \
//         -s -S -w "%{http_code}" \
//         -H "Content-Type: application/json" \
//         -H "Authorization: Bearer $ACCESS_TOKEN" \
//         -o "$TEMPORAL_FOLDER/response.json" \
//         --data-binary @- \
//         --max-time 60 \
//         --connect-timeout 10 \
//         "$IDENTITY_CREATION_ENDPOINT"
//     )

//     if [ $HTTP_CODE -eq 200 ]; then
//       break
//     fi

//     if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -eq 0 ]; then
//       echo "Network error occurred or no HTTP response was received during L2 identity creation. Retrying ($RETRY/3)..."
//       sleep 2
//       continue
//     else
//       if jq empty "$TEMPORAL_FOLDER/response_token.json" > /dev/null 2>&1; then
//         ERROR_MESSAGE=$(jq '.errors[0].message // "invalid_request"' < "$TEMPORAL_FOLDER/response_token.json" | tr -d '"')
//         echo "Error creating L2 system identity. The API endpoint returned $HTTP_CODE: $ERROR_MESSAGE. Retrying ($RETRY/3)..."
//         sleep 2
//         continue
//       else
//         echo -n "Error creating L2 system identity. The API endpoint returned $HTTP_CODE: " && cat "$TEMPORAL_FOLDER/response_token.json" | tr -d '\n' && echo " Retrying ($RETRY/3)..."
//         sleep 2
//         continue
//       fi
//     fi
//   done

//   if [ $HTTP_CODE -ne 200 ]; then
//     exit 99
//   fi

//   if jq empty "$TEMPORAL_FOLDER/response_token.json" > /dev/null 2>&1; then
//     ERROR_MESSAGE=$(jq '.errors[0].message // "NOERROR"' < "$TEMPORAL_FOLDER/response.json" | tr -d '"')
//     if [ "$ERROR_MESSAGE" != "NOERROR" ]; then
//       echo "Failed to create a New Relic System Identity L2 for Fleet Control communication authentication. Please verify that your User Key is valid and that your Account Organization has the necessary permissions to create a System Identity: $ERROR_MESSAGE"
//       exit 100
//     fi
//   fi

//   CLIENT_ID=$(/usr/local/bin/newrelic utils jq  '.data.systemIdentityCreate.clientId' < "$TEMPORAL_FOLDER/response.json" | tr -d '"' )

// mv "$TEMPORAL_FOLDER/key" "/etc/newrelic-agent-control/keys/$CLIENT_ID.key"
// sed -i 's~token_url: PLACEHOLDER~token_url: '"$TOKEN_RENEWAL_ENDPOINT"'~g' /etc/newrelic-agent-control/config.yaml
// sed -i 's/client_id: PLACEHOLDER/client_id: '"$CLIENT_ID"'/g' /etc/newrelic-agent-control/config.yaml
// sed -i 's/provider: PLACEHOLDER/provider: local/g' /etc/newrelic-agent-control/config.yaml
// sed -i 's~private_key_path: PLACEHOLDER~private_key_path: '"/etc/newrelic-agent-control/keys/$CLIENT_ID.key"'~g' /etc/newrelic-agent-control/config.yaml
// ```
