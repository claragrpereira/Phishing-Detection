library(rrcov)
library(rstudioapi)
library(fastDummies)
library(dplyr)
library(factoextra)
library(FactoMineR)
library(cluster)
library(StatMatch)
library(philentropy)
library(fpc) # for ch index
library(clValid)# for dunn index 
library(ggplot2)
library(tidyr)

rstudioapi::writeRStudioPreference("data_viewer_max_columns", 1000L)

data=read.csv("dataset_phishing.csv")

categorical_vars=c("ip","https_token", "punycode", "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "prefix_suffix", "random_domain",
             "shortening_service", "path_extension", "domain_in_brand", "brand_in_subdomain", "brand_in_path", "suspecious_tld",
             "statistical_report","login_form", "external_favicon", "iframe", "popup_window", "onmouseover", "right_clic", "empty_title",
             "domain_in_title", "domain_with_copyright", "whois_registered_domain", "dns_record", "google_index", "page_rank")

#Filtering invalid values
data=filter(data, domain_registration_length>=0 & domain_age >=0)

y=data["status"]

#Remove url name and class of the observation 
data=subset(data, select=-c(url, status))

#remove columns that are constant for all rows
data=data[vapply(data, function(x) length(unique(x)) > 1, logical(1L))]

#Define categorical co-variables as factors
data[categorical_vars] = lapply(data[categorical_vars] , factor)

#Standardize continuous co-variables
standardize_var_names=as.vector(colnames(data)[!(colnames(data) %in% categorical_vars)])

standardize_var_names=standardize_var_names[-length(standardize_var_names)]

data[, standardize_var_names]=scale(data[, standardize_var_names], center = TRUE, scale = TRUE)


#Apply FAMD to our dataset
res.famd=FAMD(data, ncp=80, graph = FALSE)

fviz_screeplot(res.famd, main="")

#Matrix of eigenvalues and variance explained by dimension
eig_list=data.frame(get_eigenvalue(res.famd))

plot(eig_list$cumulative.variance.percent/100, pch=20, axes = TRUE, xlab = "Number of PC's", ylab = "Cumulative Explained Variance Percentage", col="red")

#Contributions of variables to each dimension
var = get_famd_var(res.famd)

fviz_famd_var(res.famd, repel = TRUE)
fviz_contrib(res.famd, "var", axes = 1)
fviz_contrib(res.famd, "var", axes = 2)

quanti.var = get_famd_var(res.famd, "quanti.var")

#We can visualize both cos2 measure and "contrib" (contribution)
fviz_famd_var(res.famd, "quanti.var", col.var = "cos2",
              gradient.cols = c("#00AFBB", "#E7B800", "#FC4E07"), 
              repel = TRUE)

fviz_famd_var(res.famd, "var", col.var = "contrib",
              gradient.cols = c("#00AFBB", "#E7B800", "#FC4E07"), 
              repel = TRUE)

#Selecting the desired number of dimensions to keep
reduced_data=res.famd[["ind"]][["coord"]][,1:45]

#CLUSTERING#

#Subsampling our dataset
set.seed(16)

rows = sample(nrow(reduced_data), 1000)

subsample=reduced_data[rows,]

#Best number of clusters functions
#CH index
#Adapted from https://medium.com/@ozturkfemre/unsupervised-learning-determination-of-cluster-number-be8842cdb11

#For each number "i" between "kmin" and "kmax", the function partitions the data into "i" clusters, and
#calculates the CH index for each "i". Then returns the argmax_i, the max value, and plots all CH indexes
fviz_ch = function(data, metric, kmin, kmax) {
  ch = c()
  for (i in kmin:kmax) {
    print(i)
    if(missing(metric)) {
      km = pam(data, i, diss=TRUE)
    } else {
      km = pam(data, i, metric, diss=FALSE)
    }
     # perform clustering
    ch[i] = calinhara(data, # data
                       km$cluster, # cluster assignments
                       cn=max(km$cluster) # total cluster number
    )
    print("Done")
  }

  ch = ch[kmin:kmax]
  k = kmin:kmax
  print(which(ch==max(ch))+kmin-1)
  plot(k, ch,xlab =  "Cluster number k",
       ylab = "Caliński - Harabasz Score",
       main = "Caliński - Harabasz Plot", cex.main=1,
       col = "dodgerblue1", cex = 0.9 ,
       lty=1 , type="o" , lwd=1, pch=4,
       bty = "l",
       las = 1, cex.axis = 0.8, tcl  = -0.2)
  abline(v=which(ch==max(ch)) + 1, lwd=1, col="red", lty="dashed")
  res=which(ch==max(ch))+kmin-1
  print(max(ch))
  return(list(res[1],max(ch)))
}

#Does the same as fviz_ch but uses Dunn indexes instead
fviz_dunn <- function(data, metric, kmin, kmax) {
  if(missing(metric)==FALSE) {
    data=as.matrix(dist(data, method=metric))
  }
  k = c(kmin:kmax)
  dunnin = c()
  for (i in kmin:kmax) {
    print(i)
    km = pam(data, i, diss=TRUE)
    dunnin[i] = dunn(distance = data, clusters = km$cluster)
  }
  print(dunnin)
  dunnin = dunnin[kmin:kmax]
  print(which(dunnin==max(dunnin))+kmin-1)
  plot(k, dunnin, xlab =  "Cluster number k",
       ylab = "Dunn Index",
       main = "Dunn Plot", cex.main=1,
       col = "dodgerblue1", cex = 0.9 ,
       lty=1 , type="o" , lwd=1, pch=4,
       bty = "l",
       las = 1, cex.axis = 0.8, tcl  = -0.2)
  abline(v=which(dunnin==max(dunnin)) + 1, lwd=1, col="red", lty="dashed")
  res=which(dunnin==max(dunnin))+kmin-1
  print(max(dunnin))
  return(list(res[1],max(dunnin)))
}


#we tried to calculate gap statistic but the computational cost was too high,
#the bootstrapping step takes too long.
#fviz_nbclust(subsample, pam, method="gap_stat", k.max=50)


#Euclidean

fviz_ch(subsample,"euclidean", kmin=2, kmax=80)
fviz_dunn(subsample, "euclidean", kmin=2, kmax=50)

#Mahalanobis
mahalanobis_d=mahalanobis.dist(subsample)

fviz_ch(data=mahalanobis_d, kmin=2, kmax=50)
fviz_dunn(mahalanobis_d, kmin=2, kmax=50)

#Canberra
canberra_d=dist(subsample, method="canberra")

fviz_ch(data=canberra_d, kmin=2, kmax=80)
fviz_dunn(as.matrix(canberra_d), kmin=2, kmax=80)

#Gowers (with FAMD)
gower_d=gower.dist(subsample)

fviz_ch(data=gower_d, kmin=2, kmax=70)
fviz_dunn(data=gower_d, kmin=2, kmax=70)

#Gowers (with original dataset)
gower_d_og=gower.dist(data[rows,])

fviz_ch(data=gower_d_og, kmin=2, kmax=70)
fviz_dunn(data=gower_d_og, kmin=2, kmax=70)

#Does the same as before but all joint into a single function (it was done so it
#could automatically save all plots and their respective max values)
create_plots = function(kmin,kmax){
  ch_results=data.frame(matrix(0,nrow=2, ncol=3))
  dunn_results=data.frame(matrix(0,nrow=2, ncol=3))
  
  print("euclidean")
  png(filename="ch_euclidean.png")
  ch_results$X1=fviz_ch(subsample,"euclidean", kmin=kmin, kmax=kmax)
  dev.off()
  
  png(filename="dunn_euclidean.png")
  dunn_results$X1=fviz_dunn(subsample, "euclidean", kmin=kmin, kmax=kmax)
  dev.off()
  
  print("mahalanobis")
  mahalanobis_d=mahalanobis.dist(subsample)
  png(filename="ch_mahalanobis.png")
  ch_results$X2=fviz_ch(data=mahalanobis_d, kmin=kmin, kmax=kmax)
  dev.off()
  
  png(filename="dunn_mahalanobis.png")
  dunn_results$X2=fviz_dunn(mahalanobis_d, kmin=kmin, kmax=kmax)
  dev.off()
  
  print("gower_famd")
  gower_d=gower.dist(subsample)
  png(filename="ch_gower_famd.png")
  ch_results$X3=fviz_ch(data=gower_d, kmin=kmin, kmax=kmax)
  dev.off()
  
  png(filename="dunn_gower_famd.png")
  dunn_results$X3=fviz_dunn(gower_d, kmin=kmin, kmax=kmax)
  dev.off()

  save(ch_results, file="ch_results.Rda")
  save(dunn_results, file="dunn_results.Rda")
}

create_plots(2,90)

#Loads the results from the previous function
load("ch_results.Rda")
load("dunn_results.Rda")

#Validation of index scores using different samples
#We start by partiotining the dataset into 10 distinct samples. 

set.seed(123)

num_partitions <- 10
partitions <- list()

all_indices <- seq_len(nrow(reduced_data))

for (i in 1:num_partitions) {
  remaining_indices <- setdiff(all_indices, unlist(partitions))
  sampled_indices <- sample(remaining_indices, size = 958)
  partitions[[i]] <- reduced_data[sampled_indices, ]
}


#Generates the dataframe of CH and Dunn indexes for all possible 
#number of clusters, using k-medoids.
ch_dunn = function(data, kmin, kmax) {
  ch = c()
  dunnin = c()
  for (i in kmin:kmax) {
    print(sprintf("%s clusters.", i))
    km = pam(data, i, diss=TRUE)
    dunnin[i] = dunn(distance = data, clusters = km$cluster)
    ch[i] = calinhara(data, # data
                      km$cluster, # cluster assignments
                      cn=max(km$cluster) # total cluster number
    )
  }
  res = list(ch_list = ch[kmin:kmax], dunnin_list = dunnin[kmin:kmax])
  return (res)
}

#Same as before, but using k-means.
ch_dunn_kmeans = function(data, kmin, kmax) {
  ch = c()
  dunnin = c()
  for (i in kmin:kmax) {
    print(sprintf("%s clusters.", i))
    km = kmeans(data, centers = i)
    dunnin[i] = dunn(distance = data, clusters = km$cluster)
    ch[i] = calinhara(data, # data
                      km$cluster, # cluster assignments
                      cn=max(km$cluster) # total cluster number
    )
  }
  res = list(ch_list = ch[kmin:kmax], dunnin_list = dunnin[kmin:kmax])
  return (res)
}


# GENERATING DATAFRAMES
min_clusters = 2
max_clusters = 4
ch_df_kmeans = data.frame()
dunnin_df_kmeans = data.frame()
j = 1
for (p in partitions) {
  print(sprintf("Partition %s/10", j))
  j = j + 1
  d=dist(p, metric = "euclidean")
  metrics = ch_dunn_kmeans(d, min_clusters, max_clusters)
  print(metrics)
  ch_df = rbind(ch_df, metrics$ch_list)
  dunnin_df = rbind(dunnin_df, metrics$dunnin_list)
}
colnames(ch_df_kmeans) = seq(min_clusters, max_clusters)
colnames(dunnin_df_kmeans) = seq(min_clusters, max_clusters)

save(ch_df_kmeans, file="ch_df_kmeans.Rda")
save(dunnin_df_kmeans, file="dunnin_df_kmeans.Rda")

#Using the previously generated dataframes, we plot their data.

load("ch_df.Rda")
load("dunnin_df.Rda")

df_transposed <- as.data.frame(t(ch_df))

# Add row names as a column
df_transposed$Row <- rownames(df_transposed)

# Convert the data to long format
df_long <- gather(df_transposed, key = "Line", value = "Y", -Row)

# Convert Line to factor with levels in the original column order
df_long$Line <- factor(df_long$Line, levels = colnames(df_transposed)[-ncol(df_transposed)])
df_long$Row <- factor(df_long$Row, levels = df_transposed$Row)

ggplot(df_long, aes(x = Row, y = Y, color = Line, group = Line)) +
  geom_line(size = 1) +
  labs(x = "Number of clusters", y = "CH Index") +
  theme_minimal() +
  scale_x_discrete(breaks = df_transposed$Row[seq(1, nrow(df_transposed), by = 8)])


#Calculates the full mahalanobis distance matrix for all observations in our 
#dataset
full_mahalanobis_d=mahalanobis.dist(reduced_data)

#Does the same as fviz_ch and fviz_dunn, but prevents running "pam" two times.
#Since we now want to cluster the full dataset, it's more efficient to run pam
#only once and calculate both CH and Dunn indexes, with the same cluster object.
#This could take a while
create_plots_full = function(data,kmin,kmax){

  k = c(kmin:kmax)
  dunnin = c()
  ch = c()
  for (i in kmin:kmax) {
    print(i)
    km = pam(data, i, diss=TRUE)
    ch[i] = calinhara(data, # data
                      km$cluster, # cluster assignments
                      cn=max(km$cluster)) # total cluster number
    dunnin[i] = dunn(distance = data, clusters = km$cluster)
  }

  print("Dunnin:")
  print(dunnin)
  dunnin = dunnin[kmin:kmax]
  print(which(dunnin==max(dunnin))+kmin-1)
  png("dunn_mahalanobis_full2.png")
  plot(k, dunnin, xlab =  "Cluster number k",
       ylab = "Dunn Index",
       main = "Dunn Plot", cex.main=1,
       col = "dodgerblue1", cex = 0.9 ,
       lty=1 , type="o" , lwd=1, pch=4,
       bty = "l",
       las = 1, cex.axis = 0.8, tcl  = -0.2)
  abline(v=which(dunnin==max(dunnin)) + 1, lwd=1, col="red", lty="dashed")
  dev.off()
  res_dunn=which(dunnin==max(dunnin))+kmin-1
  save(res_dunn,file="dunnin_full2.Rda")
  
  print("CH:")
  print(ch)
  ch = ch[kmin:kmax]
  print(which(ch==max(ch))+kmin-1)
  png("ch_mahalanobis_full2.png")
  plot(k, ch,xlab =  "Cluster number k",
       ylab = "Caliński - Harabasz Score",
       main = "Caliński - Harabasz Plot", cex.main=1,
       col = "dodgerblue1", cex = 0.9 ,
       lty=1 , type="o" , lwd=1, pch=4,
       bty = "l",
       las = 1, cex.axis = 0.8, tcl  = -0.2)
  abline(v=which(ch==max(ch)) + 1, lwd=1, col="red", lty="dashed")
  dev.off()
  res_ch=which(ch==max(ch))+kmin-1
  save(res_ch, file="ch_full2.Rda")
}

#Run from 60 to 64 clusters so we could be better informed on the scores using 
#the full dataset

create_plots_full(data=full_mahalanobis_d,kmin = 60, kmax=64)

#Our final choice of number of clusters
fclusters=pam(full_mahalanobis_d, k=62, diss=TRUE)
#save(fclusters, file="fclusters.Rda")

load("fclusters.Rda")

#Original data so we can compare clusters
data=read.csv("dataset_phishing.csv")

data=filter(data, domain_registration_length>=0 & domain_age >=0)

data=subset(data, select=-c(url))
data$status=factor(data$status)

y_counts=data.frame(matrix(nrow=2, ncol=62))
y=data$status
for(i in 1:62){
  y_counts[,i]=table(y[fclusters$clustering==i])
}

summary(data[fclusters$clustering==2,])

#Compare clusters to true labels
website_df = as.data.frame(t(y_counts))
website_df$websites = 1:nrow(website_df)

website_df = reshape2::melt(website_df, id.vars = "websites")
ggplot(website_df, aes(x = websites, y=value ,fill=variable)) +
  geom_bar(stat = "identity", position = "stack") +
  labs(x = "Clusters", y = "Count", title = "Legitimate and Phishing Websites by Cluster") +
  scale_fill_manual(values = c("royalblue2","indianred1"), name = "Category", labels = c("Legitimate", "Phishing")) +
  theme_minimal()
