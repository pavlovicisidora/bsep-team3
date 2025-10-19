export interface Template {
  id: number;
  name: string;
  issuer: {
    subjectDN: string;
  };
}

export interface TemplateCreate {
  name: string;
  issuerSerialNumber: string;
  commonNameRegex: string;
  subjectAlternativeNamesRegex?: string; 
  timeToLiveDays: number;
  keyUsage: string[];
  extendedKeyUsage: string[];
}

