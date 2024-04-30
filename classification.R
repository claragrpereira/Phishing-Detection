#-------------------------- SUpervised Classification----------------

#------------libraries--------------------------
library(FactoMineR)
library(caret)
library(ggplot2)
library(plotly)
library(plyr)
library(dplyr)
library(psych)
library(vcd)
library(factoextra)

#-------------data load--------------------------
data <- read.csv("dataset_phishing.csv")


#-------------Preprocessing---------------------
categorical_vars=c("ip","https_token", "punycode", "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "prefix_suffix", "random_domain",
                   "shortening_service", "path_extension", "domain_in_brand", "brand_in_subdomain", "brand_in_path", "suspecious_tld",
                   "statistical_report","login_form", "external_favicon", "iframe", "popup_window", "onmouseover", "right_clic", "empty_title",
                   "domain_in_title", "domain_with_copyright", "whois_registered_domain", "dns_record", "google_index", "page_rank")

data=filter(data, domain_registration_length>=0 & domain_age >=0)

y=data["status"]

#Remove url name and class
data=subset(data, select=-c(url, status))

#remove columns that are constant for all rows
data=data[vapply(data, function(x) length(unique(x)) > 1, logical(1L))]

data[categorical_vars] = lapply(data[categorical_vars] , factor)

standerdize_var_names=as.vector(colnames(data)[!(colnames(data) %in% categorical_vars)])

standerdize_var_names=standerdize_var_names[-length(standerdize_var_names)]

data[, standerdize_var_names]=scale(data[, standerdize_var_names], center = TRUE, scale = TRUE)

#----------Dimensionality Reduction: FAMD -------
res.famd=FAMD(data, ncp=80, graph=FALSE)
reduced_data=res.famd[["ind"]][["coord"]][,1:45]
reduced_data=as.data.frame(reduced_data)

#--------------Train-test split------------------
# Split the data into training and testing sets (80% training, 20% testing)
set.seed(16)

train_indices <- sample(1:nrow(data), 0.8 * nrow(data))
train_data <- reduced_data[train_indices, ]
test_data <- reduced_data[-train_indices, ]

y <- as.factor(as.numeric(factor(y$status)))
y_train<- y[train_indices]
y_test <- y[-train_indices]

# Combine the retained components with the response variable
x_train <- cbind(train_data, status = y_train)

# Keep only the first 45 components
x_test <- as.data.frame(test_data)
names(x_test) <- names(reduced_data)

#------------Classification------------------------------
#-------------KNN----------------------------------------

# KNN
model_knn <- train(status ~ ., data = x_train, method = "knn", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_knn <- predict(model_knn, newdata=x_test)

# Confusion matrix
conf_matrix <- confusionMatrix(predictions_knn, y_test)

# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score

# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")

#--------------Decision Tree-----------------------------------
# Decision tree
model_dt <- train(status ~ ., data = x_train, method = "rpart", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_dt <- predict(model_dt, newdata=x_test)

# Confusion matrix
conf_matrix <- confusionMatrix(predictions_dt, y_test)

# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score

# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")

#------------------------Random Forest--------------------------
# Random Forest - Warning: This could take a while

model_nb <- train(status ~ ., data = x_train, method = "rf", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_nb <- predict(model_nb, newdata=x_test)

# Confusion matrix
conf_matrix <- confusionMatrix(predictions_nb, y_test)

# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score

# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")

#---------------------Naive Bayes--------------------------------
# Naive Bayes
model_nbd <- train(status ~ ., data = x_train, method = "naive_bayes", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_nbd <- predict(model_nbd, newdata=x_test)

# Confusion matrix
conf_matrix <- confusionMatrix(predictions_nbd, y_test)

# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score

# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")

#---------------------------SVM--------------------------
# SVM Linear Kernel
model_svm <- train(status ~ ., data = x_train, method = "svmLinear", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_svm <- predict(model_svm, newdata=x_test)

# Confusion matrix
conf_matrix <- confusionMatrix(predictions_svm, y_test)

# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score

# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")


famd_results <- res.famd$eig
famd_loadings <- res.famd$var$coord

# Get variable importance scores from the Random-Forest model
importance_scores <- varImp(model_nb)$importance[1]  # Assuming only one metric is used

# Identify the top N most important features (you can choose N based on your needs)
top_features <- rownames(importance_scores)[1:45]

# Extract the loadings for the top features
top_features_loadings <- famd_loadings[, top_features]

feature_contributions <- data.frame(
  Feature = rownames(top_features_loadings),
  Contribution = rowSums(top_features_loadings * importance_scores[,1])
)

# Normalize contributions to make them interpretable
normalized_contributions <- feature_contributions$Contribution / sum(abs(feature_contributions$Contribution))


# Add normalized contributions to the data frame
feature_contributions$Normalized_Contribution <- normalized_contributions

# Order the features by contribution
feature_contributions <- feature_contributions[order(abs(feature_contributions$Contribution), decreasing = TRUE), ]

# Print the result
print(feature_contributions)


library(ggplot2)
# Filter the top 20 features
top_20_features <- head(feature_contributions[order(-abs(feature_contributions$Normalized_Contribution)), ], 20)

# Create a bar plot for the top 20 features without legend
ggplot(top_20_features, aes(x = Feature, y = Normalized_Contribution, fill = Feature)) +
  geom_bar(stat = "identity") +
  labs(
       x = "Feature",
       y = "Normalized Contribution") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1, size = 8),  # Adjust text angle and size
        legend.position = "none")  # Remove legend


# Create a bar plot
ggplot(feature_contributions, aes(x = Feature, y = Normalized_Contribution, fill = Feature)) +
  geom_bar(stat = "identity") +
  labs(title = "Normalized Contributions of Features",
       x = "Feature",
       y = "Normalized Contribution") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1)) + theme(legend.position = "none")  # Remove legend

#------------Classification Using Clusters------------------------------
load("fclusters.Rda")

#--------------Train-test split------------------
# Split the data into training and testing sets (80% training, 20% testing)

y_clusters=data.frame(fclusters$clustering)

y_clusters$fclusters.clustering <- factor(y_clusters$fclusters.clustering)
y_train_clusters <- y_clusters[train_indices, ]
y_test_clusters <- y_clusters[-train_indices, ]

# Combine the retained components with the response variable
x_train <- cbind(train_data, status = y_train_clusters)

x_test <- as.data.frame(test_data)
names(x_test) <- names(reduced_data)

y_counts=data.frame(matrix(nrow=2, ncol=62))

for(i in 1:62){
  y_counts[,i]=table(y[fclusters$clustering==i])
}

most_probable_class <- apply(y_counts, 2, which.max)
#-------------KNN----------------------------------------
model_knn <- train(status ~ ., data = x_train, method = "knn", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_knn <- predict(model_knn, newdata=x_test)

real_pred=data.frame(matrix(nrow=length(x_test[,1]), ncol=1))
for(i in 1:length(x_test[,1])){
  real_pred[i,]=most_probable_class[predictions_knn[i]]
}

names(real_pred)=c("pred")
pred=factor(real_pred$pred)
# Confusion matrix
conf_matrix <- confusionMatrix(pred, y_test)

# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score



# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")

#------------------------Random Forest--------------------------
# Random Forest - Warning: This could take a while
model_nb <- train(status ~ ., data = x_train, method = "rf", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_nb <- predict(model_nb, newdata=x_test)

real_pred=data.frame(matrix(nrow=length(x_test[,1]), ncol=1))
for(i in 1:length(x_test[,1])){
  real_pred[i,]=most_probable_class[predictions_nb[i]]
}

names(real_pred)=c("pred")
pred=factor(real_pred$pred)
# Confusion matrix
conf_matrix <- confusionMatrix(pred, y_test)


# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score

# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")

#---------------------------SVM--------------------------
# SVM Linear Kernel
model_svm <- train(status ~ ., data = x_train, method = "svmLinear", trControl = trainControl(method = "cv",number = 5))

#predict
predictions_svm <- predict(model_svm, newdata=x_test)

real_pred=data.frame(matrix(nrow=length(x_test[,1]), ncol=1))
for(i in 1:length(x_test[,1])){
  real_pred[i,]=most_probable_class[predictions_svm[i]]
}

names(real_pred)=c("pred")
pred=factor(real_pred$pred)
# Confusion matrix
conf_matrix <- confusionMatrix(pred, y_test)

# Extract metrics
accuracy <- conf_matrix$overall["Accuracy"]
precision <- conf_matrix$byClass["Pos Pred Value"]  # Precision
sensitivity <- conf_matrix$byClass["Sensitivity"]   # Sensitivity (Recall)
f1_score <- conf_matrix$byClass["F1"]               # F1 Score

# Print or use the metrics as needed
cat("Accuracy:", accuracy, "\n")
cat("Precision:", precision, "\n")
cat("Sensitivity:", sensitivity, "\n")
cat("F1 Score:", f1_score, "\n")

