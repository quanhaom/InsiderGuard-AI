import {
    useEffect,
    useState
} from "react";

import {
    useParams
} from "react-router-dom";

import api from "../api/client";

import "../styles/investigation.css";


function Investigation(){

    const {
        id
    } = useParams();


    const [
        report,
        setReport
    ] = useState(null);


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        error,
        setError
    ] = useState("");



    useEffect(()=>{

        loadReport();

    },[]);



    async function loadReport(){

        try{

            const response =
                await api.get(
                    `/investigator/incident/${id}`
                );


            setReport(
                response.data
            );


        }
        catch(err){

            console.error(err);

            setError(
                "Investigation report not found"
            );

        }
        finally{

            setLoading(false);

        }

    }



    async function generateReport(){

        try{

            setLoading(true);


            await api.post(
                `/investigator/incident/${id}/generate`
            );


            await loadReport();


        }
        catch(err){

            console.error(err);

            setError(
                "Could not generate report"
            );

        }

    }



    if(loading){

        return (

            <div className="screen-message">

                Loading investigation...

            </div>

        );

    }



    if(error){

        return (

            <div className="screen-message">

                <h2>
                    {error}
                </h2>


                <button
                    onClick={generateReport}
                >

                    Generate AI Report

                </button>

            </div>

        );

    }



    return (

        <div className="investigation-page">


            <header className="investigation-header">

                <div>

                    <h1>
                        AI Investigation Report
                    </h1>


                    <p>
                        Incident #{report.incident_id}
                    </p>

                </div>


                <div className="confidence">

                    Confidence

                    <strong>
                        {report.confidence}%
                    </strong>

                </div>


            </header>



            <section className="investigation-card">


                <h2>
                    Executive Summary
                </h2>


                <p>
                    {report.summary}
                </p>


            </section>




            <section className="investigation-card">


                <h2>
                    Analysis
                </h2>


                <p>
                    {report.analysis}
                </p>


            </section>





            <section className="investigation-grid">


                <div className="investigation-card">

                    <h2>
                        MITRE ATT&CK
                    </h2>


                    {
                        report.mitre_techniques
                        &&
                        report.mitre_techniques.length > 0

                        ?

                        report.mitre_techniques.map(
                            (item,index)=>(

                                <div
                                    className="tag"
                                    key={index}
                                >
                                    {item}
                                </div>

                            )

                        )

                        :

                        <p>
                            No techniques identified
                        </p>

                    }


                </div>




                <div className="investigation-card">


                    <h2>
                        Recommendations
                    </h2>


                    <ul>

                    {
                        report.recommendations.map(
                            (item,index)=>(

                                <li
                                    key={index}
                                >
                                    {item}
                                </li>

                            )
                        )
                    }

                    </ul>


                </div>


            </section>





            <section className="investigation-card">


                <h2>
                    Model Information
                </h2>


                <p>
                    Model:
                    {" "}
                    {report.model_name}
                </p>


                <p>
                    Generated:
                    {" "}
                    {
                        new Date(
                            report.created_at
                        )
                        .toLocaleString()
                    }
                </p>


            </section>



        </div>

    );

}


export default Investigation;