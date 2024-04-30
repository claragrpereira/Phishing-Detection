#install.packages("plotly")
#install.packages("ggplot2")
#install.packages("plyr")
#install.packages("dplyr")
#install.packages("psych")
#install.packages("vcd")

library(ggplot2)
library(plotly)
library(plyr)
library(dplyr)
library(psych)
library(vcd)


####################################
#DATA TREATMENT
####################################

data <- read.csv("dataset_phishing.csv")
phdata = filter(data, domain_registration_length>=0 & domain_age >=0)

dummy_vars=c("ip","https_token", "punycode", "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "prefix_suffix", "random_domain",
             "shortening_service", "path_extension", "domain_in_brand", "brand_in_subdomain", "brand_in_path", "suspecious_tld",
             "statistical_report","login_form", "external_favicon", "iframe", "popup_window", "onmouseover", "right_clic", "empty_title",
             "domain_in_title", "domain_with_copyright", "whois_registered_domain", "dns_record", "google_index", "page_rank")

#Remove url name and class
phdata=subset(phdata, select=-c(url))

#Remove columns that are constant for all rows
phdata=phdata[vapply(phdata, function(x) length(unique(x)) > 1, logical(1L))]
summary(phdata)

categorical_df = phdata[,dummy_vars]
numeric_df = subset(phdata, select=-c(ip, https_token, punycode, port, tld_in_path, tld_in_subdomain, abnormal_subdomain, prefix_suffix, random_domain,
                                        shortening_service, path_extension, domain_in_brand, brand_in_subdomain, brand_in_path, suspecious_tld,
                                        statistical_report,login_form, external_favicon, iframe, popup_window, onmouseover, right_clic, empty_title,
                                        domain_in_title, domain_with_copyright, whois_registered_domain, dns_record, google_index,page_rank,status)
)

#Continuous is a subset of numeric
continuous=c("ratio_digits_url","ratio_digits_host","avg_words_raw","avg_word_host","avg_word_path",
             "ratio_intHyperlinks","ratio_extHyperlinks","ratio_extRedirection","ratio_extErrors",
             "links_in_tags","ratio_intMedia","ratio_extMedia","safe_anchor")
continuous_df = phdata[,continuous]

####################################
##################################
#SUMMARY OF VARS
####################################
####################################

summary(categorical_df)
summary(numeric_df)
summary(continuous_df)

####################################
####################################
#HISTOGRAMS
####################################
####################################
#DISCRETE VARS
####################################

#Variáveis com 3º Quartil = 0:
#nb_or, nb_at, nb_qm, nb_and, nb_eq, nb_underscore, nb_percent, nb_comma, nb_semicolumn, nb_dollar, nb_space, nb_com, http_in_path, phish_hints....


histograms <- function(col,title){
  
  ran1 = range(phdata[[col[1]]])
  ran2 = range(phdata[[col[2]]])
  ran3 = range(phdata[[col[3]]])
  ran4 = range(phdata[[col[4]]])
  
  
  plot_col1 <- plot_ly(data = phdata, x = phdata[[col[1]]], type = "histogram", marker = list(color = 'rgb(20,30,200)',line = list(color = 'rgb(139,58,58)', width=1.5)), xbins=list(start=ran1[1], end=ran1[2], size=(ran1[2] - ran1[1])/20)) %>%
    layout(
      xaxis = list(title = title[1], tickvals= c(), ticktext = c()),
      yaxis = list(title = "Frequency")
    )
  
  
  plot_col2 <- plot_ly(data = phdata, x = phdata[[col[2]]], type = "histogram",marker = list(color = 'rgb(205,92,92)',line = list(color = 'rgb(139,58,58)', width=1.5)),xbins=list(start=ran2[1], end=ran2[2], size=(ran2[2] - ran2[1])/20)) %>%
    layout(
      xaxis = list(title = title[2],tickvals= c(), ticktext = c()),
      yaxis = list(title = "Frequency") 
    )
  
  plot_col3 <- plot_ly(data = phdata, x = phdata[[col[3]]], type = "histogram", marker = list(color = 'rgb(20,205,92)', line = list(color = 'rgb(139,58,58)', width=1.5)),xbins=list(start=ran3[1], end=ran3[2], size=(ran3[2] - ran3[1])/20)) %>%
    layout(
      xaxis = list(title = title[3], tickvals= c(), ticktext = c()),
      yaxis = list(title = "Frequency")
    )
  
  plot_col4 <- plot_ly(data = phdata, x = phdata[[col[4]]], type = "histogram", marker = list(color = 'rgb(205,92,30)',line = list(color = 'rgb(139,58,58)', width=1.5)),xbins=list(start=ran4[1], end=ran4[2], size=(ran4[2] - ran4[1])/20)) %>%
    layout(
      xaxis = list(title = title[4], tickvals= c(), ticktext = c()),
      yaxis = list(title = "Frequency")
    )
  
  subplot_list <- subplot(plot_col1, plot_col2,plot_col3, plot_col4, nrows = 4,titleX=TRUE, titleY=TRUE)

  # Display the subplot
  subplot_list
}

histograms(c("length_url", "length_hostname", "nb_dots", "nb_slash"), c("Length of URL", "Length of Host Name", "Number of Dots", "Number of Slashes"))
histograms(c("length_words_raw", "char_repeat", "shortest_word_host", "longest_word_host"), c("length_words_raw", "char_repeat", "shortest_word_host", "longest_word_host"))
histograms(c("shortest_word_path","longest_words_raw", "longest_word_path","nb_hyperlinks"),c("shortest_word_path","longest_words_raw", "lonsgest_word_path","nb_hyperlinks"))
histograms(c("domain_registration_length", "domain_age", "web_traffic", "page_rank"), c("domain_registration_length", "domain_age", "web_traffic", "page_rank"))


####################################
#CONTINUOUS VARS
####################################

histograms(c("ratio_digits_url","ratio_digits_host","avg_words_raw","avg_word_host"), c("ratio_digits_url","ratio_digits_host","avg_words_raw","avg_word_host"))
histograms(c("avg_word_path","ratio_intHyperlinks","ratio_extHyperlinks","ratio_extRedirection"), c("avg_word_path","ratio_intHyperlinks","ratio_extHyperlinks","ratio_extRedirection"))
histograms(c("ratio_extErrors","links_in_tags","ratio_intMedia","ratio_extMedia"), c("ratio_extErrors","links_in_tags","ratio_intMedia","ratio_extMedia"))


####################################
#STATUS
####################################
y_phishing=data["status"]
y_phishing = data.frame(sapply(y_phishing, function(x) as.numeric(x == "phishing")))

plot_y <- plot_ly(data = phdata, x = sapply(phdata[["status"]], function(x) as.numeric(x == "phishing")), type = "histogram", marker = list(color = 'rgb(139,58,58)',line = list(color = 'rgb(100,58,58)', width=1.5))) %>%
  layout(
    xaxis = list(title = "Status", tickvals= c(), ticktext = c()),
    yaxis = list(title = "Frequency")
  )

plot_y



####################################
####################################
#CORRELATION
####################################
####################################

####################################
#NUMERIC VS NUMERIC
####################################
#51x51 matrix - can be 4 20x20 matrixes? for visualization
cor_numeric_numeric <- cor(numeric_df, numeric_df, method = "pearson",  use = "pairwise.complete.obs")
print(cor_numeric_numeric)

#visualization

# correlation matrix is symmetrical!!! redundant information is being showed
heatmap_num <- plot_ly(z = cor_numeric_numeric[51:1,], type = "heatmap",
                    zmin = -1, zmax = 1, colors = colorRamp(c("blue", "white", "red")),
                    y = rev(colnames(cor_numeric_numeric)), x = colnames(cor_numeric_numeric)) #%>%
 # layout(title = "Pearson's r"
#  )
heatmap_num

####################################
#CATEGORICAL VS CATEGORICAL (2 levels) 
####################################
#27x27 matrix
#categorical association w/ 2 levels (Phi Coefficient)

categorical_df2 = subset(categorical_df, select = -c(statistical_report, page_rank))
n_row = ncol(categorical_df2)
n_col = n_row
cor_cat2_cat2 <- matrix(NA, nrow = n_row, ncol = n_col)
colnames(cor_cat2_cat2) <- colnames(categorical_df2)
rownames(cor_cat2_cat2) <- colnames(categorical_df2)

for (i in 1:n_row){
  for (j in 1:n_col) {
    frequency_table <- table(categorical_df2[, i], categorical_df2[, j])
    phi_coef <- phi(as.matrix(frequency_table), digits=6)
    cor_cat2_cat2[i, j] <- phi_coef
  }
}

print(cor_cat2_cat2)

heatmap_cat2 <- plot_ly(z = cor_cat2_cat2[27:1,], type = "heatmap",
                       zmin = -1, zmax = 1, colors = colorRamp(c("blue", "white", "red")),
                       y = rev(colnames(cor_cat2_cat2)), x = colnames(cor_cat2_cat2)) 
heatmap_cat2

####################################
#CATEGORICAL VS CATEGORICAL (2 levels or more) 
####################################
#only for statistical_report: 1x12 matrix
#cramer's V - coeff between 0 e 1 

n_col <- ncol(categorical_df2)
n_row <- 1
cor_catmore2_cat2 <- matrix(NA, nrow = n_row, ncol = n_col)
diag(cor_catmore2_cat2) <- 1
rownames(cor_catmore2_cat2) <- colnames(phdata$statistical_report)
colnames(cor_catmore2_cat2) <- colnames(categorical_df2)

for (i in 1:n_row) {
  for (j in 1:n_col) {
    contingency_table <- table(phdata$statistical_report, categorical_df2[, j])
    cramersv_result <-  assocstats(as.matrix(contingency_table))$cramer
    cor_catmore2_cat2[i, j] <- cramersv_result
  }
}

for (col in colnames(categorical_df2)){
  print(col) 
  print("&")
  print(2)
}


print(cor_catmore2_cat2)

heatmap_catmore2 <- plot_ly(z = cor_catmore2_cat2, type = "heatmap",
                        zmin = 0, zmax = 1, colors = colorRamp(c("white", "red")),
                        y = "statistical_report", x = colnames(cor_catmore2_cat2)) %>%
  layout(title = "Cramer's V"
  )
heatmap_catmore2

####################################
#NUMERIC VS CATEGORICAL
####################################
#51x27 matrix
#correlation numeric vs categorical w/ 2 cat (Coefficient Point-biserial)


num_row <- ncol(numeric_df)
num_col <- ncol(categorical_df2)
cor_numeric_cat2 <- matrix(NA, nrow = num_row, ncol = num_col)
rownames(cor_numeric_cat2) <- colnames(numeric_df)
colnames(cor_numeric_cat2) <- colnames(categorical_df2)

for (i in 1:num_row) {
  for (j in 1:num_col) {
    biserial_result <- cor.test(numeric_df[,i], as.numeric(categorical_df2[,j]))
    cor_numeric_cat2[i, j] <- biserial_result$estimate
  }
}

print(cor_numeric_cat2)

heatmap_numcat2 <- plot_ly(z = cor_numeric_cat2[52:1,], type = "heatmap",
                            zmin = -1, zmax = 1, colors = colorRamp(c("blue", "white", "red")),
                            y = rev(rownames(cor_numeric_cat2)), x = colnames(cor_numeric_cat2)) %>%
  layout(title = "Coefficient Point-biserial"
  )
heatmap_numcat2

